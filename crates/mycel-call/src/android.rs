//! Android audio: two AAudio streams set up the way phone-call apps do. The
//! voice-communication input preset turns on the phone's own echo canceller,
//! noise suppressor and gain control, and the voice-communication usage
//! routes the far end like a call (earpiece / speaker / headset policy,
//! call volume).

use anyhow::{Context, Result, anyhow, bail};
use ndk::audio::{
    AudioCallbackResult, AudioContentType, AudioDirection, AudioFormat, AudioInputPreset, AudioPerformanceMode,
    AudioSharingMode, AudioStream, AudioStreamBuilder, AudioUsage,
};

use crate::audio::{AudioHandle, AudioIo, AudioPorts, MIC_DENIED};
use crate::codec::SAMPLE_RATE;

/// Mic and speaker for a call, with the phone's echo cancellation.
pub struct VoiceCallAudio;

impl AudioIo for VoiceCallAudio {
    fn describe(&self) -> String {
        "Voice call audio (echo cancellation)".into()
    }

    fn echo_cancellation(&self) -> bool {
        true
    }

    /// The UI asks for the permission (Android only lets an activity ask);
    /// here we only check, so a refusal gives a clear message.
    fn prepare(&self) -> Result<()> {
        match mic_allowed() {
            Ok(true) => Ok(()),
            Ok(false) => bail!(MIC_DENIED),
            Err(e) => {
                eprintln!("[mycel] can't check the microphone permission: {e:#}");
                Ok(())
            }
        }
    }

    fn open(&self, ports: AudioPorts) -> Result<AudioHandle> {
        let AudioPorts { mut mic, mut speaker } = ports;
        let input = AudioStreamBuilder::new()
            .context("AAudio")?
            .direction(AudioDirection::Input)
            .format(AudioFormat::PCM_Float)
            .channel_count(1)
            .sample_rate(SAMPLE_RATE as i32)
            .sharing_mode(AudioSharingMode::Shared)
            .performance_mode(AudioPerformanceMode::LowLatency)
            .input_preset(AudioInputPreset::VoiceCommunication)
            .data_callback(Box::new(move |_stream, data, frames| {
                // SAFETY: AAudio hands us `frames` mono f32 samples.
                let samples = unsafe { std::slice::from_raw_parts(data as *const f32, frames.max(0) as usize) };
                let _ = mic.push_partial_slice(samples);
                AudioCallbackResult::Continue
            }))
            .error_callback(Box::new(|_stream, e| eprintln!("[mycel] microphone stream error: {e:?}")))
            .open_stream()
            .map_err(|e| anyhow!("can't open the microphone ({e:?})"))?;
        let output = AudioStreamBuilder::new()
            .context("AAudio")?
            .direction(AudioDirection::Output)
            .format(AudioFormat::PCM_Float)
            .channel_count(1)
            .sample_rate(SAMPLE_RATE as i32)
            .sharing_mode(AudioSharingMode::Shared)
            .performance_mode(AudioPerformanceMode::LowLatency)
            .usage(AudioUsage::VoiceCommunication)
            .content_type(AudioContentType::Speech)
            .data_callback(Box::new(move |_stream, data, frames| {
                // SAFETY: AAudio wants `frames` mono f32 samples written here.
                let out = unsafe { std::slice::from_raw_parts_mut(data as *mut f32, frames.max(0) as usize) };
                let got = speaker.pop_partial_slice(out).0.len();
                out[got..].fill(0.0);
                AudioCallbackResult::Continue
            }))
            .error_callback(Box::new(|_stream, e| eprintln!("[mycel] speaker stream error: {e:?}")))
            .open_stream()
            .map_err(|e| anyhow!("can't open the speaker ({e:?})"))?;
        for (stream, what) in [(&input, "microphone"), (&output, "speaker")] {
            // We asked for 48 kHz mono; AAudio converts in shared mode, but
            // refuse anything else rather than play at the wrong speed.
            if stream.sample_rate() != SAMPLE_RATE as i32 || stream.channel_count() != 1 {
                bail!("the {what} runs at {} Hz x{}, not 48 kHz mono", stream.sample_rate(), stream.channel_count());
            }
        }
        input.request_start().map_err(|e| anyhow!("can't start the microphone ({e:?})"))?;
        output.request_start().map_err(|e| anyhow!("can't start the speaker ({e:?})"))?;
        Ok(AudioHandle::new(Streams { _input: input, _output: output }))
    }
}

/// Closing a stream (on drop) stops its callbacks.
struct Streams {
    _input: AudioStream,
    _output: AudioStream,
}

// SAFETY: AAudio streams may be stopped and closed from any thread.
unsafe impl Send for Streams {}

/// `Context.checkSelfPermission(RECORD_AUDIO) == PERMISSION_GRANTED`.
fn mic_allowed() -> Result<bool> {
    let ctx = ndk_context::android_context();
    // SAFETY: tao keeps the process's JavaVM and Context alive for the app's life.
    let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }?;
    let mut env = vm.attach_current_thread()?;
    // SAFETY: a global reference to the app's Context, borrowed.
    let context = unsafe { jni::objects::JObject::from_raw(ctx.context().cast()) };
    let permission = env.new_string("android.permission.RECORD_AUDIO")?;
    let granted = env
        .call_method(&context, "checkSelfPermission", "(Ljava/lang/String;)I", &[(&permission).into()])?
        .i()?;
    Ok(granted == 0)
}
