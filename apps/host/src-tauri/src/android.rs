//! Android glue that works with no activity (no window) at all.
//!
//! Tauri opens the runtime when the first activity is created. After a
//! reboot, an app update, a restart of the sticky `MycelService`, or a
//! WorkManager catch-up there is no activity, so `MycelRuntime.kt` calls
//! [`Java_dev_mycel_host_MycelRuntime_start`] to open the same runtime
//! (`crate::start_in_background`), for an existing profile only. A window
//! opened later adopts it (`crate::start`).
//!
//! Calls into Kotlin go through the application `Context` that
//! `MycelRuntime.start` hands over, or tao's once an activity exists, and
//! the app's class loader (a native thread's `FindClass` only sees system
//! classes).
//!
//! Iroh's DNS resolver (`n0-dns-resolver`) and `netdev` read the system's
//! network settings through `ndk_context`, which tao fills in when the first
//! activity is created. A background start fills it in itself
//! ([`share_context`]); `MainActivity` hands it back just before tao takes
//! over ([`Java_dev_mycel_host_MycelRuntime_handOverContext`]), because tao
//! asserts it is empty. Without it, DNS falls back to public resolvers.

use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
use jni::sys::{JNI_FALSE, JNI_TRUE, jboolean, jint, jlong};
use jni::{JNIEnv, JavaVM};

use crate::background::BackgroundStatus;

/// The VM and the application `Context`, from `MycelRuntime.start`.
static APPLICATION: OnceLock<(JavaVM, GlobalRef)> = OnceLock::new();

/// Who filled in `ndk_context`: never both (tao asserts it's empty).
#[derive(Default)]
struct NdkContext {
    /// A background start did, with [`APPLICATION`].
    ours: bool,
    /// An activity is being created: tao fills it in from now on.
    tao: bool,
}

static NDK_CONTEXT: Mutex<NdkContext> = Mutex::new(NdkContext { ours: false, tao: false });

/// Give `ndk_context` users (DNS, interface listing) the application
/// `Context` when no activity has.
fn share_context() {
    let Some((vm, context)) = APPLICATION.get() else { return };
    let mut ndk = NDK_CONTEXT.lock().unwrap_or_else(|e| e.into_inner());
    if ndk.ours || ndk.tao {
        return;
    }
    // SAFETY: the VM and a global reference held in a static for the life
    // of the process; nobody else has filled it in (`tao` is unset, and
    // MainActivity sets it before tao's onCreate runs).
    unsafe {
        ndk_context::initialize_android_context(vm.get_java_vm_pointer().cast(), context.as_obj().as_raw().cast())
    };
    ndk.ours = true;
}

/// `MycelRuntime.handOverContext()`, from `MainActivity.onCreate` before
/// tao's: empty `ndk_context` if a background start filled it in, and never
/// fill it in again.
///
/// Known hazard, small but real: until tao fills it in again (the rest of
/// `WryActivity.onCreate` before `Rust.onCreate`: `AppCompatActivity`'s
/// setup and two `registerForActivityResult` calls, milliseconds) the
/// context is empty, and only some lookups survive that. The DNS resolver
/// catches the missing context and falls back to public resolvers for that
/// query. `netdev` 0.46 does not: it probes once, behind `catch_unwind`, and
/// caches "available" in a `OnceLock`; every later lookup calls
/// `ndk_context::android_context()` unguarded, which panics when empty. A
/// network-interface query that lands in the window (netwatch reads them
/// whenever the network may have changed)
/// panics that task, and the runtime may stop noticing network changes
/// until Mycel restarts. Only a window opened after a background start in
/// the same process hits this. Closing it needs tao to accept a filled-in
/// context (it asserts it is empty), or netdev to guard every lookup.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_mycel_host_MycelRuntime_handOverContext(_env: JNIEnv, _class: JClass) {
    let mut ndk = NDK_CONTEXT.lock().unwrap_or_else(|e| e.into_inner());
    if ndk.ours {
        // SAFETY: filled in by `share_context`, and tao hasn't run yet.
        unsafe { ndk_context::release_android_context() };
        ndk.ours = false;
    }
    ndk.tao = true;
}

/// Run `f` with a JNI environment and the application `Context`.
fn with_context<R>(f: impl FnOnce(&mut JNIEnv, &JObject) -> jni::errors::Result<R>) -> jni::errors::Result<R> {
    if let Some((vm, context)) = APPLICATION.get() {
        let mut env = vm.attach_current_thread()?;
        return f(&mut env, context.as_obj());
    }
    // No background start: an activity exists, and tao keeps the process's
    // JavaVM and application Context alive.
    let ctx = ndk_context::android_context();
    // SAFETY: tao's JavaVM pointer, valid for the life of the process.
    let vm = unsafe { JavaVM::from_raw(ctx.vm().cast()) }?;
    let mut env = vm.attach_current_thread()?;
    // SAFETY: a global reference to the application Context, borrowed.
    let context = unsafe { JObject::from_raw(ctx.context().cast()) };
    f(&mut env, &context)
}

/// Call a static method of one of Mycel's own Kotlin classes, clearing any
/// Java exception it throws (it becomes the error).
fn call_static<'local>(
    env: &mut JNIEnv<'local>,
    context: &JObject,
    class: &str,
    method: &str,
    signature: &str,
    args: &[JValue],
) -> jni::errors::Result<jni::objects::JValueOwned<'local>> {
    let loader = env.call_method(context, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])?.l()?;
    let name = env.new_string(class)?;
    let class = env
        .call_method(&loader, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;", &[JValue::Object(&name)])?
        .l()?;
    let res = env.call_static_method(JClass::from(class), method, signature, args);
    if res.is_err() {
        let _ = env.exception_clear();
    }
    res
}

/// `MycelService.notify(context, title, body)` (gen/android/.../MycelService.kt).
pub(crate) fn notify(title: &str, body: &str) -> jni::errors::Result<()> {
    with_context(|env, context| {
        let (title, body) = (env.new_string(title)?, env.new_string(body)?);
        call_static(
            env,
            context,
            "dev.mycel.host.MycelService",
            "notify",
            "(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V",
            &[JValue::Object(context), JValue::Object(&title), JValue::Object(&body)],
        )
        .map(|_| ())
    })
}

pub(crate) fn background_status() -> Result<BackgroundStatus, String> {
    let json = with_context(|env, context| {
        let value = call_static(
            env,
            context,
            "dev.mycel.host.MycelRuntime",
            "backgroundStatus",
            "(Landroid/content/Context;)Ljava/lang/String;",
            &[JValue::Object(context)],
        )?
        .l()?;
        let text: String = env.get_string(&JString::from(value))?.into();
        Ok(text)
    })
    .map_err(|e| format!("background status unavailable: {e}"))?;
    BackgroundStatus::from_android_json(&json)
}

pub(crate) fn request_battery_exemption() -> Result<(), String> {
    with_context(|env, context| {
        call_static(
            env,
            context,
            "dev.mycel.host.MycelRuntime",
            "requestBatteryExemption",
            "(Landroid/content/Context;)V",
            &[JValue::Object(context)],
        )
        .map(|_| ())
    })
    .map_err(|e| format!("can't open the battery setting: {e}"))
}

/// `MycelRuntime.start(context, dataDir)`: open the runtime with no window,
/// for an existing profile only. Blocks (Kotlin calls it off the main
/// thread). True once a runtime is running in this process.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_mycel_host_MycelRuntime_start(
    mut env: JNIEnv,
    _class: JClass,
    context: JObject,
    data_dir: JString,
) -> jboolean {
    let remembered = (|| -> jni::errors::Result<String> {
        if APPLICATION.get().is_none() {
            let app = env.call_method(&context, "getApplicationContext", "()Landroid/content/Context;", &[])?.l()?;
            let app = env.new_global_ref(app)?;
            let _ = APPLICATION.set((env.get_java_vm()?, app));
        }
        Ok(env.get_string(&data_dir)?.into())
    })();
    let Ok(dir) = remembered else {
        let _ = env.exception_clear();
        eprintln!("mycel-host: background start: bad arguments");
        return JNI_FALSE;
    };
    share_context();
    // A panic must not unwind into the JVM.
    let started = std::panic::catch_unwind(|| crate::start_in_background(PathBuf::from(dir))).unwrap_or(false);
    if started { JNI_TRUE } else { JNI_FALSE }
}

/// `MycelRuntime.beginCatchUp()`: a ticket for one catch-up, taken before
/// anything that may be cancelled.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_mycel_host_MycelRuntime_beginCatchUp(_env: JNIEnv, _class: JClass) -> jlong {
    crate::background::begin_catch_up() as jlong
}

/// `MycelRuntime.catchUp(ticket, seconds)`: one catch-up round (WorkManager's
/// backstop, or a sticky restart that couldn't become a foreground service).
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_mycel_host_MycelRuntime_catchUp(
    _env: JNIEnv,
    _class: JClass,
    ticket: jlong,
    seconds: jint,
) -> jboolean {
    let budget = Duration::from_secs(seconds.clamp(0, 600) as u64);
    let done = std::panic::catch_unwind(|| crate::background::catch_up_now(ticket as u64, budget)).unwrap_or(false);
    if done { JNI_TRUE } else { JNI_FALSE }
}

/// `MycelRuntime.cancelCatchUp(ticket)`: WorkManager stopped that job.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_mycel_host_MycelRuntime_cancelCatchUp(_env: JNIEnv, _class: JClass, ticket: jlong) {
    crate::background::cancel_catch_up(ticket as u64);
}
