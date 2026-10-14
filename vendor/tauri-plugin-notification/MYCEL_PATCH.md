# Mycel iOS notification fixes

Based on tauri-plugin-notification 2.5.1 (upstream d4835d0e947179bac24a383212792d74be3ebe4f).

Delivered iOS notifications outlive the plugin's in-memory notification map. The upstream handler force-unwraps that map when converting a retained notification for tap or getActive, crashing after a process restart. Use the OS request for title/body/category/id and optional original metadata instead.

Treat the sound name `default` as `UNNotificationSound.default`, so callers can request the system sound without a bundled sound file.

Store the latest default tap's opaque notification identifier until consumed through the Rust-only `take_pending_action` extension. A cold-launch tap can arrive before the webview registers its event listener; draining this pending identifier after registration and on resume preserves the action. Dismissals do not become tap actions.

Bound the optional notification metadata cache to 256 records, protect it with a lock, and prune records on cancellation/removal. Evicted or removed records still convert safely from retained OS request content.

Regression: `tests/retained-notification/run.sh` compiles the actual handler and UserNotifications framework on macOS with minimal Tauri/model stubs, then verifies conversion of an OS request in a newly constructed handler and the encoded tap payload. The actual iOS host build validates the full Swift plugin.

Packaging: the crate's own `Cargo.lock` from the published package is not kept. Cargo ignores lock files of path dependencies; this plugin builds from the workspace's `Cargo.lock` like every other crate here.
