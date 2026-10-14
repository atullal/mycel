//! Apple audio (macOS, iOS, iPadOS): Apple's voice-processing I/O unit
//! (AUVoiceProcessingIO, the one FaceTime uses) for echo cancellation, noise
//! suppression and gain control, plus the microphone permission check. On
//! iPhone and iPad the app's audio session must also be switched to
//! play-and-record for the call.

use std::ffi::c_void;
use std::ptr::NonNull;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use objc2::rc::Retained;
use objc2::runtime::{AnyClass, Bool};
use objc2::msg_send;
use objc2_audio_toolbox::{
    AURenderCallbackStruct, AudioComponentDescription, AudioComponentFindNext, AudioComponentInstanceDispose,
    AudioComponentInstanceNew, AudioOutputUnitStart, AudioOutputUnitStop, AudioUnit, AudioUnitInitialize,
    AudioUnitRender, AudioUnitRenderActionFlags, AudioUnitSetProperty, AudioUnitUninitialize,
    kAudioOutputUnitProperty_EnableIO, kAudioOutputUnitProperty_SetInputCallback, kAudioUnitManufacturer_Apple,
    kAudioUnitProperty_SetRenderCallback, kAudioUnitProperty_StreamFormat, kAudioUnitScope_Global,
    kAudioUnitScope_Input, kAudioUnitScope_Output, kAudioUnitSubType_VoiceProcessingIO, kAudioUnitType_Output,
};
use objc2_core_audio_types::{
    AudioBuffer, AudioBufferList, AudioStreamBasicDescription, AudioTimeStamp, kAudioFormatFlagIsFloat,
    kAudioFormatFlagIsPacked, kAudioFormatLinearPCM,
};
use objc2_foundation::NSString;

use crate::audio::{AudioHandle, AudioIo, AudioPorts, DeviceAudio, MIC_DENIED};
use crate::codec::SAMPLE_RATE;

#[link(name = "AVFoundation", kind = "framework")]
unsafe extern "C" {}

// ─────────────────────────── microphone permission ───────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MicPermission {
    NotDetermined,
    Restricted,
    Denied,
    Authorized,
}

fn capture_device_class() -> Option<&'static AnyClass> {
    AnyClass::get(c"AVCaptureDevice")
}

/// `AVMediaTypeAudio`.
fn media_audio() -> Retained<NSString> {
    NSString::from_str("soun")
}

/// What the user decided about microphone access (never prompts).
pub fn mic_permission() -> MicPermission {
    let Some(cls) = capture_device_class() else { return MicPermission::Authorized };
    let media = media_audio();
    // SAFETY: +[AVCaptureDevice authorizationStatusForMediaType:] takes an
    // NSString and returns an NSInteger.
    let status: isize = unsafe { msg_send![cls, authorizationStatusForMediaType: &*media] };
    match status {
        0 => MicPermission::NotDetermined,
        1 => MicPermission::Restricted,
        2 => MicPermission::Denied,
        _ => MicPermission::Authorized,
    }
}

/// Ask once if the user hasn't decided yet (the system shows its prompt
/// with the app's NSMicrophoneUsageDescription); error if not allowed.
pub fn ensure_mic_permission() -> Result<()> {
    match mic_permission() {
        MicPermission::Authorized => Ok(()),
        MicPermission::Denied | MicPermission::Restricted => bail!(MIC_DENIED),
        MicPermission::NotDetermined => {
            let Some(cls) = capture_device_class() else { return Ok(()) };
            let (tx, rx) = std::sync::mpsc::channel::<bool>();
            let block = block2::RcBlock::new(move |granted: Bool| {
                let _ = tx.send(granted.as_bool());
            });
            let media = media_audio();
            // SAFETY: +[AVCaptureDevice requestAccessForMediaType:completionHandler:]
            // takes an NSString and a `void (^)(BOOL)` block, which it copies.
            let _: () = unsafe {
                msg_send![cls, requestAccessForMediaType: &*media, completionHandler: &*block]
            };
            match rx.recv_timeout(Duration::from_secs(120)) {
                Ok(true) => Ok(()),
                Ok(false) => bail!(MIC_DENIED),
                Err(_) => bail!("No answer to the microphone permission prompt."),
            }
        }
    }
}

// ─────────────────────────── voice processing I/O ───────────────────────────

/// Mic and speakers through AUVoiceProcessingIO: the system removes what the
/// speakers play from what the microphone hears, so no headphones needed.
/// Falls back to plain devices if the unit can't start.
pub struct VoiceProcessingAudio;

impl AudioIo for VoiceProcessingAudio {
    fn describe(&self) -> String {
        "Voice processing (echo cancellation)".into()
    }

    fn echo_cancellation(&self) -> bool {
        true
    }

    fn prepare(&self) -> Result<()> {
        ensure_mic_permission()
    }

    fn open(&self, ports: AudioPorts) -> Result<AudioHandle> {
        #[cfg(target_os = "ios")]
        let session = CallSession::activate()?;
        let handle = match VoiceUnit::start(ports) {
            Ok(unit) => AudioHandle::new(unit),
            Err((e, ports)) => {
                eprintln!("[mycel] voice processing unavailable ({e:#}); using plain audio devices");
                DeviceAudio.open(ports)?
            }
        };
        // The session ends after the unit stops (fields drop in order).
        #[cfg(target_os = "ios")]
        let handle = AudioHandle::new((handle, session));
        Ok(handle)
    }
}

// ─────────────────────────── iOS audio session ───────────────────────────

/// While a call runs: the app's audio session in play-and-record, voice chat
/// mode (the system's call tuning), on the loudspeaker unless headphones or
/// a Bluetooth headset are connected. Dropping it hands audio back to other
/// apps.
#[cfg(target_os = "ios")]
struct CallSession;

#[cfg(target_os = "ios")]
impl CallSession {
    fn session() -> Result<&'static objc2::runtime::AnyObject> {
        let cls = AnyClass::get(c"AVAudioSession").ok_or_else(|| anyhow!("no AVAudioSession"))?;
        // SAFETY: +[AVAudioSession sharedInstance] returns the process-wide
        // session, which lives as long as the app.
        let session: *mut objc2::runtime::AnyObject = unsafe { msg_send![cls, sharedInstance] };
        // SAFETY: a valid object or nil.
        unsafe { session.as_ref() }.ok_or_else(|| anyhow!("no audio session"))
    }

    fn activate() -> Result<CallSession> {
        let session = Self::session()?;
        let category = NSString::from_str("AVAudioSessionCategoryPlayAndRecord");
        let mode = NSString::from_str("AVAudioSessionModeVoiceChat");
        // AllowBluetooth (0x4) | DefaultToSpeaker (0x8)
        let options: usize = 0x4 | 0x8;
        let no_error = std::ptr::null_mut::<*mut objc2::runtime::AnyObject>();
        // SAFETY: -setCategory:mode:options:error: and -setActive:error: take
        // NSStrings, an NSUInteger, a BOOL and an optional NSError** (NULL).
        let ok: Bool = unsafe { msg_send![session, setCategory: &*category, mode: &*mode, options: options, error: no_error] };
        if !ok.as_bool() {
            bail!("couldn't set up audio for the call");
        }
        let ok: Bool = unsafe { msg_send![session, setActive: Bool::YES, error: no_error] };
        if !ok.as_bool() {
            bail!("couldn't start audio for the call (is another app using the microphone?)");
        }
        Ok(CallSession)
    }
}

#[cfg(target_os = "ios")]
impl Drop for CallSession {
    fn drop(&mut self) {
        if let Ok(session) = Self::session() {
            let no_error = std::ptr::null_mut::<*mut objc2::runtime::AnyObject>();
            // NotifyOthersOnDeactivation (1): music apps may resume.
            // SAFETY: -setActive:withOptions:error: with a NULL NSError**.
            let _: Bool = unsafe { msg_send![session, setActive: Bool::NO, withOptions: 1usize, error: no_error] };
        }
    }
}

/// State the CoreAudio callbacks use. Lives in a Box whose address is the
/// callbacks' refcon; freed only after the unit is stopped and disposed.
struct Shared {
    unit: AudioUnit,
    mic: rtrb::Producer<f32>,
    speaker: rtrb::Consumer<f32>,
    scratch: Vec<f32>,
}

struct VoiceUnit {
    unit: AudioUnit,
    shared: *mut Shared,
}

// The unit and its callback state are only touched by CoreAudio's I/O thread
// and by `Drop` after the unit stopped.
unsafe impl Send for VoiceUnit {}

fn os(status: i32, what: &str) -> Result<()> {
    if status != 0 { Err(anyhow!("{what} failed (OSStatus {status})")) } else { Ok(()) }
}

fn set<T>(unit: AudioUnit, prop: u32, scope: u32, element: u32, value: &T) -> Result<()> {
    // SAFETY: `value` is a live T of the size passed.
    let st = unsafe {
        AudioUnitSetProperty(unit, prop, scope, element, value as *const T as *const c_void, std::mem::size_of::<T>() as u32)
    };
    os(st, "AudioUnitSetProperty")
}

const MAX_FRAMES: usize = 8192;

impl VoiceUnit {
    fn start(ports: AudioPorts) -> std::result::Result<VoiceUnit, (anyhow::Error, AudioPorts)> {
        let desc = AudioComponentDescription {
            componentType: kAudioUnitType_Output,
            componentSubType: kAudioUnitSubType_VoiceProcessingIO,
            componentManufacturer: kAudioUnitManufacturer_Apple,
            componentFlags: 0,
            componentFlagsMask: 0,
        };
        // SAFETY: plain C calls with valid pointers.
        let comp = unsafe { AudioComponentFindNext(std::ptr::null_mut(), NonNull::from(&desc)) };
        if comp.is_null() {
            return Err((anyhow!("no voice processing unit"), ports));
        }
        let mut unit: AudioUnit = std::ptr::null_mut();
        let st = unsafe { AudioComponentInstanceNew(comp, NonNull::from(&mut unit)) };
        if st != 0 || unit.is_null() {
            return Err((anyhow!("voice processing unit failed to open ({st})"), ports));
        }
        let shared = Box::into_raw(Box::new(Shared {
            unit,
            mic: ports.mic,
            speaker: ports.speaker,
            scratch: vec![0.0; MAX_FRAMES],
        }));
        match Self::configure(unit, shared) {
            Ok(()) => Ok(VoiceUnit { unit, shared }),
            Err(e) => {
                // SAFETY: the unit never started; dispose it, then take the ports back.
                unsafe {
                    AudioUnitUninitialize(unit);
                    AudioComponentInstanceDispose(unit);
                    let s = Box::from_raw(shared);
                    Err((e, AudioPorts { mic: s.mic, speaker: s.speaker }))
                }
            }
        }
    }

    fn configure(unit: AudioUnit, shared: *mut Shared) -> Result<()> {
        let on: u32 = 1;
        // bus 1 = microphone (input), bus 0 = speaker (output)
        set(unit, kAudioOutputUnitProperty_EnableIO, kAudioUnitScope_Input, 1, &on)?;
        set(unit, kAudioOutputUnitProperty_EnableIO, kAudioUnitScope_Output, 0, &on)?;
        let fmt = AudioStreamBasicDescription {
            mSampleRate: SAMPLE_RATE as f64,
            mFormatID: kAudioFormatLinearPCM,
            mFormatFlags: kAudioFormatFlagIsFloat | kAudioFormatFlagIsPacked,
            mBytesPerPacket: 4,
            mFramesPerPacket: 1,
            mBytesPerFrame: 4,
            mChannelsPerFrame: 1,
            mBitsPerChannel: 32,
            mReserved: 0,
        };
        // what we get from the mic, and what we give the speaker: 48 kHz mono f32
        set(unit, kAudioUnitProperty_StreamFormat, kAudioUnitScope_Output, 1, &fmt)?;
        set(unit, kAudioUnitProperty_StreamFormat, kAudioUnitScope_Input, 0, &fmt)?;
        let input = AURenderCallbackStruct { inputProc: Some(on_input), inputProcRefCon: shared as *mut c_void };
        set(unit, kAudioOutputUnitProperty_SetInputCallback, kAudioUnitScope_Global, 1, &input)?;
        let render = AURenderCallbackStruct { inputProc: Some(on_render), inputProcRefCon: shared as *mut c_void };
        set(unit, kAudioUnitProperty_SetRenderCallback, kAudioUnitScope_Input, 0, &render)?;
        // SAFETY: configured unit.
        unsafe {
            os(AudioUnitInitialize(unit), "AudioUnitInitialize")?;
            os(AudioOutputUnitStart(unit), "AudioOutputUnitStart")?;
        }
        Ok(())
    }
}

impl Drop for VoiceUnit {
    fn drop(&mut self) {
        // SAFETY: stop first so no callback runs, then free their state.
        unsafe {
            AudioOutputUnitStop(self.unit);
            AudioUnitUninitialize(self.unit);
            AudioComponentInstanceDispose(self.unit);
            drop(Box::from_raw(self.shared));
        }
    }
}

/// The mic has `frames` new samples: render them out of bus 1.
unsafe extern "C-unwind" fn on_input(
    refcon: NonNull<c_void>,
    flags: NonNull<AudioUnitRenderActionFlags>,
    time: NonNull<AudioTimeStamp>,
    bus: u32,
    frames: u32,
    _data: *mut AudioBufferList,
) -> i32 {
    // SAFETY: refcon is our `Shared`, alive while the unit runs.
    let s = unsafe { &mut *(refcon.as_ptr() as *mut Shared) };
    let n = (frames as usize).min(MAX_FRAMES);
    let mut list = AudioBufferList {
        mNumberBuffers: 1,
        mBuffers: [AudioBuffer {
            mNumberChannels: 1,
            mDataByteSize: (n * 4) as u32,
            mData: s.scratch.as_mut_ptr() as *mut c_void,
        }],
    };
    // SAFETY: buffer list points at `n` floats of scratch space.
    let st = unsafe { AudioUnitRender(s.unit, flags.as_ptr(), time, bus, n as u32, NonNull::from(&mut list)) };
    if st == 0 {
        let _ = s.mic.push_partial_slice(&s.scratch[..n]);
    }
    st
}

/// The speaker needs `frames` samples.
unsafe extern "C-unwind" fn on_render(
    refcon: NonNull<c_void>,
    _flags: NonNull<AudioUnitRenderActionFlags>,
    _time: NonNull<AudioTimeStamp>,
    _bus: u32,
    frames: u32,
    data: *mut AudioBufferList,
) -> i32 {
    // SAFETY: refcon is our `Shared`; `data` is CoreAudio's buffer list.
    let s = unsafe { &mut *(refcon.as_ptr() as *mut Shared) };
    let Some(list) = (unsafe { data.as_mut() }) else { return 0 };
    let bufs = unsafe { std::slice::from_raw_parts_mut(list.mBuffers.as_mut_ptr(), list.mNumberBuffers as usize) };
    for b in bufs {
        if b.mData.is_null() {
            continue;
        }
        let len = (b.mDataByteSize as usize / 4).min(frames as usize);
        let out = unsafe { std::slice::from_raw_parts_mut(b.mData as *mut f32, len) };
        let got = s.speaker.pop_partial_slice(out).0.len();
        out[got..].fill(0.0);
    }
    0
}

#[cfg(test)]
mod tests {
    /// Prints whether this process may use the microphone. Only reads the
    /// status, never prompts:
    /// `cargo test -p mycel-call mic_status -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn mic_status() {
        eprintln!("microphone permission: {:?}", super::mic_permission());
    }
}
