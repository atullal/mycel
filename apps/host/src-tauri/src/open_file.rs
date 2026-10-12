//! Open a received attachment the platform's way. On a computer that is the
//! default app for the file (the webview uses the opener plugin directly).
//! Phones have no "default app" for a file inside Mycel's sandbox, so:
//! - iPhone and iPad: the share sheet (Save to Files, AirDrop, open in Books,
//!   Photos and so on);
//! - Android: an "Open with" chooser, through a content:// URI from
//!   MainActivity's FileProvider.

use std::path::{Path, PathBuf};

use tauri::AppHandle;

/// Open `path`, which must be a decrypted attachment under `<data dir>/files/`
/// (nothing else in the data dir, like keys, may leave the app this way).
pub fn open(app: &AppHandle, data_dir: &Path, path: &str) -> Result<(), String> {
    let path = attachment_path(data_dir, path)?;
    platform_open(app, path)
}

fn attachment_path(data_dir: &Path, path: &str) -> Result<PathBuf, String> {
    let files = std::fs::canonicalize(data_dir.join("files"))
        .map_err(|e| format!("no attachments folder: {e}"))?;
    let file = std::fs::canonicalize(path).map_err(|e| format!("can't open {path}: {e}"))?;
    if !file.starts_with(&files) || !file.is_file() {
        return Err(format!("{path} is not a downloaded attachment"));
    }
    Ok(file)
}

#[cfg(desktop)]
fn platform_open(app: &AppHandle, path: PathBuf) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    app.opener()
        .open_path(path.to_string_lossy(), None::<&str>)
        .map_err(|e| e.to_string())
}

#[cfg(target_os = "ios")]
fn platform_open(app: &AppHandle, path: PathBuf) -> Result<(), String> {
    use objc2::MainThreadMarker;
    use objc2::rc::Retained;
    use objc2::runtime::AnyObject;
    use objc2_core_foundation::{CGPoint, CGRect, CGSize};
    use objc2_foundation::{NSArray, NSString, NSURL};
    use objc2_ui_kit::{UIActivityViewController, UIViewController};
    use tauri::Manager;

    let window = app.get_webview_window("main").ok_or("no Mycel window")?;
    window
        .with_webview(move |webview| {
            // with_webview runs this on the main thread.
            let Some(mtm) = MainThreadMarker::new() else { return };
            // SAFETY: Tauri hands out the webview's live UIViewController.
            let Some(vc) = (unsafe { (webview.view_controller() as *mut UIViewController).as_ref() }) else {
                return;
            };
            let url = NSURL::fileURLWithPath(&NSString::from_str(&path.to_string_lossy()));
            let item: Retained<AnyObject> = url.into();
            let items = NSArray::from_retained_slice(&[item]);
            // SAFETY: a plain alloc/init with an array of NSURLs.
            let sheet = unsafe {
                UIActivityViewController::initWithActivityItems_applicationActivities(
                    mtm.alloc::<UIActivityViewController>(),
                    &items,
                    None,
                )
            };
            // On iPad the sheet is a popover and needs an anchor, or UIKit
            // throws. Point it at the middle of the composer area.
            if let (Some(popover), Some(view)) = (sheet.popoverPresentationController(), vc.view()) {
                let b = view.bounds();
                popover.setSourceView(Some(&view));
                popover.setSourceRect(CGRect::new(
                    CGPoint::new(b.size.width / 2.0, b.size.height - 96.0),
                    CGSize::new(1.0, 1.0),
                ));
            }
            vc.presentViewController_animated_completion(&sheet, true, None);
        })
        .map_err(|e| e.to_string())
}

#[cfg(target_os = "android")]
fn platform_open(app: &AppHandle, path: PathBuf) -> Result<(), String> {
    use tauri::Manager;

    let window = app.get_webview_window("main").ok_or("no Mycel window")?;
    window
        .with_webview(move |webview| {
            webview.jni_handle().exec(move |env, activity, _webview| {
                let Ok(arg) = env.new_string(path.to_string_lossy()) else { return };
                // MainActivity.openFile (gen/android/.../MainActivity.kt)
                let res = env.call_method(activity, "openFile", "(Ljava/lang/String;)V", &[(&arg).into()]);
                if res.is_err() {
                    eprintln!("mycel-host: attachment open failed");
                    let _ = env.exception_clear();
                }
            });
        })
        .map_err(|e| e.to_string())
}
