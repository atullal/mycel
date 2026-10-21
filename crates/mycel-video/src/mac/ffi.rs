//! The few CoreMedia / CoreVideo / VideoToolbox C functions this crate
//! uses, declared directly (CF types as opaque pointers; CF dictionaries
//! and strings are toll-free bridged to their Foundation classes).

#![allow(non_upper_case_globals, non_snake_case, clippy::upper_case_acronyms)]

use std::ffi::c_void;

pub type OSStatus = i32;
pub type CFTypeRef = *const c_void;
pub type CFStringRef = *const c_void;
pub type CFDictionaryRef = *const c_void;
pub type CFArrayRef = *const c_void;
pub type CVPixelBufferRef = *mut c_void;
pub type CMSampleBufferRef = *mut c_void;
pub type CMBlockBufferRef = *mut c_void;
pub type CMFormatDescriptionRef = *mut c_void;
pub type VTSessionRef = *mut c_void;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CMTime {
    pub value: i64,
    pub timescale: i32,
    pub flags: u32,
    pub epoch: i64,
}

impl CMTime {
    /// `kCMTimeInvalid`
    pub const INVALID: CMTime = CMTime { value: 0, timescale: 0, flags: 0, epoch: 0 };

    pub fn micros(us: i64) -> CMTime {
        // kCMTimeFlags_Valid
        CMTime { value: us, timescale: 1_000_000, flags: 1, epoch: 0 }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CMVideoDimensions {
    pub width: i32,
    pub height: i32,
}

pub type VTCompressionOutputCallback =
    unsafe extern "C-unwind" fn(*mut c_void, *mut c_void, OSStatus, u32, CMSampleBufferRef);
pub type VTDecompressionOutputCallback =
    unsafe extern "C-unwind" fn(*mut c_void, *mut c_void, OSStatus, u32, CVPixelBufferRef, CMTime, CMTime);

#[repr(C)]
pub struct VTDecompressionOutputCallbackRecord {
    pub callback: VTDecompressionOutputCallback,
    pub refcon: *mut c_void,
}

/// 'avc1'
pub const kCMVideoCodecType_H264: u32 = u32::from_be_bytes(*b"avc1");
/// '420v': NV12, video range (what cameras and the encoder like best).
pub const kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange: u32 = u32::from_be_bytes(*b"420v");
pub const kCVPixelFormatType_420YpCbCr8BiPlanarFullRange: u32 = u32::from_be_bytes(*b"420f");
pub const kCVPixelBufferLock_ReadOnly: u64 = 1;
pub const kCMBlockBufferAssureMemoryNowFlag: u32 = 1;
pub const kVTEncodeInfo_FrameDropped: u32 = 1 << 1;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    pub fn CFRetain(cf: CFTypeRef) -> CFTypeRef;
    pub fn CFRelease(cf: CFTypeRef);
    pub fn CFArrayGetCount(a: CFArrayRef) -> isize;
    pub fn CFArrayGetValueAtIndex(a: CFArrayRef, i: isize) -> *const c_void;
    pub fn CFDictionaryGetValue(d: CFDictionaryRef, key: *const c_void) -> *const c_void;
    pub static kCFBooleanTrue: CFTypeRef;
    pub static kCFBooleanFalse: CFTypeRef;
}

#[link(name = "CoreVideo", kind = "framework")]
unsafe extern "C" {
    pub fn CVPixelBufferCreate(
        allocator: *const c_void,
        width: usize,
        height: usize,
        format: u32,
        attrs: CFDictionaryRef,
        out: *mut CVPixelBufferRef,
    ) -> i32;
    pub fn CVPixelBufferLockBaseAddress(pb: CVPixelBufferRef, flags: u64) -> i32;
    pub fn CVPixelBufferUnlockBaseAddress(pb: CVPixelBufferRef, flags: u64) -> i32;
    pub fn CVPixelBufferGetWidth(pb: CVPixelBufferRef) -> usize;
    pub fn CVPixelBufferGetHeight(pb: CVPixelBufferRef) -> usize;
    pub fn CVPixelBufferGetPixelFormatType(pb: CVPixelBufferRef) -> u32;
    pub fn CVPixelBufferGetBaseAddressOfPlane(pb: CVPixelBufferRef, plane: usize) -> *mut u8;
    pub fn CVPixelBufferGetBytesPerRowOfPlane(pb: CVPixelBufferRef, plane: usize) -> usize;
    pub fn CVPixelBufferGetHeightOfPlane(pb: CVPixelBufferRef, plane: usize) -> usize;
    pub fn CVPixelBufferGetWidthOfPlane(pb: CVPixelBufferRef, plane: usize) -> usize;
    pub static kCVPixelBufferPixelFormatTypeKey: CFStringRef;
    pub static kCVPixelBufferIOSurfacePropertiesKey: CFStringRef;
}

#[link(name = "CoreMedia", kind = "framework")]
unsafe extern "C" {
    pub fn CMSampleBufferGetImageBuffer(sb: CMSampleBufferRef) -> CVPixelBufferRef;
    pub fn CMSampleBufferGetDataBuffer(sb: CMSampleBufferRef) -> CMBlockBufferRef;
    pub fn CMSampleBufferGetFormatDescription(sb: CMSampleBufferRef) -> CMFormatDescriptionRef;
    pub fn CMSampleBufferGetSampleAttachmentsArray(sb: CMSampleBufferRef, create: u8) -> CFArrayRef;
    pub fn CMBlockBufferGetDataLength(bb: CMBlockBufferRef) -> usize;
    pub fn CMBlockBufferCopyDataBytes(bb: CMBlockBufferRef, offset: usize, len: usize, dst: *mut c_void) -> OSStatus;
    pub fn CMBlockBufferCreateWithMemoryBlock(
        allocator: *const c_void,
        memory: *mut c_void,
        block_len: usize,
        block_allocator: *const c_void,
        custom_source: *const c_void,
        offset: usize,
        data_len: usize,
        flags: u32,
        out: *mut CMBlockBufferRef,
    ) -> OSStatus;
    pub fn CMBlockBufferReplaceDataBytes(
        src: *const c_void,
        dst: CMBlockBufferRef,
        offset: usize,
        len: usize,
    ) -> OSStatus;
    pub fn CMSampleBufferCreateReady(
        allocator: *const c_void,
        data: CMBlockBufferRef,
        format: CMFormatDescriptionRef,
        num_samples: isize,
        num_timing: isize,
        timing: *const c_void,
        num_sizes: isize,
        sizes: *const usize,
        out: *mut CMSampleBufferRef,
    ) -> OSStatus;
    pub fn CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
        desc: CMFormatDescriptionRef,
        index: usize,
        ptr: *mut *const u8,
        size: *mut usize,
        count: *mut usize,
        nal_header_len: *mut i32,
    ) -> OSStatus;
    pub fn CMVideoFormatDescriptionCreateFromH264ParameterSets(
        allocator: *const c_void,
        count: usize,
        pointers: *const *const u8,
        sizes: *const usize,
        nal_header_len: i32,
        out: *mut CMFormatDescriptionRef,
    ) -> OSStatus;
    pub fn CMVideoFormatDescriptionGetDimensions(desc: CMFormatDescriptionRef) -> CMVideoDimensions;
    pub static kCMSampleAttachmentKey_NotSync: CFStringRef;
}

#[link(name = "VideoToolbox", kind = "framework")]
unsafe extern "C" {
    pub fn VTCompressionSessionCreate(
        allocator: *const c_void,
        width: i32,
        height: i32,
        codec: u32,
        encoder_spec: CFDictionaryRef,
        source_attrs: CFDictionaryRef,
        compressed_allocator: *const c_void,
        callback: VTCompressionOutputCallback,
        refcon: *mut c_void,
        out: *mut VTSessionRef,
    ) -> OSStatus;
    pub fn VTCompressionSessionEncodeFrame(
        session: VTSessionRef,
        image: CVPixelBufferRef,
        pts: CMTime,
        duration: CMTime,
        frame_props: CFDictionaryRef,
        source_refcon: *mut c_void,
        info_out: *mut u32,
    ) -> OSStatus;
    pub fn VTCompressionSessionCompleteFrames(session: VTSessionRef, until: CMTime) -> OSStatus;
    pub fn VTCompressionSessionPrepareToEncodeFrames(session: VTSessionRef) -> OSStatus;
    pub fn VTCompressionSessionInvalidate(session: VTSessionRef);
    pub fn VTPixelTransferSessionCreate(allocator: *const c_void, out: *mut VTSessionRef) -> OSStatus;
    pub fn VTPixelTransferSessionTransferImage(
        session: VTSessionRef,
        source: CVPixelBufferRef,
        destination: CVPixelBufferRef,
    ) -> OSStatus;
    pub fn VTPixelTransferSessionInvalidate(session: VTSessionRef);
    pub fn VTDecompressionSessionCreate(
        allocator: *const c_void,
        format: CMFormatDescriptionRef,
        decoder_spec: CFDictionaryRef,
        dest_attrs: CFDictionaryRef,
        callback: *const VTDecompressionOutputCallbackRecord,
        out: *mut VTSessionRef,
    ) -> OSStatus;
    pub fn VTDecompressionSessionDecodeFrame(
        session: VTSessionRef,
        sample: CMSampleBufferRef,
        flags: u32,
        source_refcon: *mut c_void,
        info_out: *mut u32,
    ) -> OSStatus;
    pub fn VTDecompressionSessionWaitForAsynchronousFrames(session: VTSessionRef) -> OSStatus;
    pub fn VTDecompressionSessionInvalidate(session: VTSessionRef);
    pub fn VTSessionSetProperty(session: VTSessionRef, key: CFStringRef, value: CFTypeRef) -> OSStatus;
    pub fn VTSessionCopyProperty(
        session: VTSessionRef,
        key: CFStringRef,
        alloc: *const c_void,
        out: *mut CFTypeRef,
    ) -> OSStatus;

    pub static kVTCompressionPropertyKey_RealTime: CFStringRef;
    pub static kVTCompressionPropertyKey_ProfileLevel: CFStringRef;
    pub static kVTCompressionPropertyKey_AllowFrameReordering: CFStringRef;
    pub static kVTCompressionPropertyKey_MaxKeyFrameInterval: CFStringRef;
    pub static kVTCompressionPropertyKey_MaxKeyFrameIntervalDuration: CFStringRef;
    pub static kVTCompressionPropertyKey_AverageBitRate: CFStringRef;
    pub static kVTCompressionPropertyKey_DataRateLimits: CFStringRef;
    pub static kVTCompressionPropertyKey_ExpectedFrameRate: CFStringRef;
    // iOS has it only from 17.4 (Mycel supports 16.4): a missing symbol would
    // stop the app from launching. iPhones and iPads always encode in hardware.
    #[cfg(target_os = "macos")]
    pub static kVTCompressionPropertyKey_UsingHardwareAcceleratedVideoEncoder: CFStringRef;
    pub static kVTProfileLevel_H264_High_AutoLevel: CFStringRef;
    pub static kVTProfileLevel_H264_Baseline_AutoLevel: CFStringRef;
    pub static kVTEncodeFrameOptionKey_ForceKeyFrame: CFStringRef;
    pub static kVTVideoEncoderSpecification_EnableLowLatencyRateControl: CFStringRef;
    #[cfg(target_os = "macos")]
    pub static kVTVideoEncoderSpecification_EncoderID: CFStringRef;
    pub static kVTDecompressionPropertyKey_RealTime: CFStringRef;
}
