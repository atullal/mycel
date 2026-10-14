# Mycel on every platform

One codebase, five apps: the Tauri host (`apps/host`) with the Rust runtime
(`crates/mycel-node`) inside, built for macOS, iPhone and iPad, Android, Windows
and Linux. The UI is the same web UI everywhere; under 720 px wide it switches
to the phone layout (tab bar at the bottom).

**Every device must run the same build.** The wire format still changes between
builds.

## What works where

| | macOS | iPhone / iPad | Android | Windows | Linux |
|---|---|---|---|---|---|
| Messages, groups, files of any size | yes | yes | yes | yes | yes |
| Same Wi-Fi / LAN (mDNS) | yes | yes¹ | yes² | yes | yes |
| Internet (relays, hole punching, DHT lookup) | yes | yes | yes | yes | yes |
| Mesh routing and store-and-forward through other devices | yes | yes | yes | yes | yes |
| Peer-to-peer Wi-Fi with no network (AWDL) | yes | on, untested³ | not yet (Wi-Fi Direct) | no | Wi-Fi Direct code, off by default |
| Bluetooth LE link | yes | on, untested³ | not yet | not yet | BlueZ, never run on hardware |
| Voice calls | echo cancelled | echo cancelled | echo cancelled⁴ | no echo cancellation⁵ | no echo cancellation⁵ |
| Sending video | yes | on, untested³ | yes⁷ | yes⁷ | yes, with GStreamer's H.264 encoders⁷ |
| Opening a received file | default app | share sheet | "Open with" | default app | default app |
| Keeps running in the background | yes | during calls⁶ | yes⁶ | yes | yes |
| Notifications (new messages, incoming calls)⁸ | yes | yes, while running | yes | yes | yes |

1. iOS asks for Local Network access the first time; without it, only internet
   paths work.
2. `MainActivity` holds a Wi-Fi multicast lock so mDNS packets get through.
3. The Mac code (Network.framework, CoreBluetooth, AVFoundation and
   VideoToolbox) now runs on iOS too, with the front camera and upright
   frames for a phone held in portrait. It hasn't been tried on an iPhone or
   iPad yet; the Simulator has neither radio (Bluetooth reports
   "Unsupported" and the app carries on). iOS only allows these in the
   foreground.
4. AAudio's voice-communication input preset (`crates/mycel-call/src/android.rs`).
5. Plain devices through `cpal`: use headphones, or the far end hears itself.
6. **Android:** a foreground service (`MycelService`, a quiet "Mycel is
   connected" notification) keeps the runtime running with the app in the
   background or swiped away from recents; opening it again gets a new
   window on the same runtime. Tested on the emulator. **iPhone and iPad:**
   iOS suspends apps. Calls carry on in the background (background audio),
   and going to the background asks iOS for its usual grace period so sends
   finish. After that, messages arrive when Mycel is opened again, or
   through a keeper or store-and-forward on other devices. Waking a
   suspended iPhone needs Apple's push service, which needs a server; Mycel
   has none.
7. Android, Windows and Linux have no VideoToolbox, so the web view captures
   the camera (`getUserMedia`) and encodes H.264 with WebCodecs, in hardware
   where the platform has it, and the runtime sends those frames like a
   Mac's (`crates/mycel-video/src/web.rs`, `packages/sdk/src/webcam.ts`).
   Tested on the Android 14 emulator against a desktop peer: video both
   ways, and the phone's frames decode with ffmpeg (720×1280, Constrained
   Baseline). Windows and Linux are checked in CI without a camera
   (`scripts/ci/video-probe.html`): headless Edge, the engine under
   WebView2, with Chromium's fake camera, and WebKitGTK 2.50 and 2.52 with
   WebKit's mock camera both capture and encode. On Linux the app turns on
   WebKitGTK's camera capture, and encodes through a canvas (WebKitGTK fails
   on frames taken straight from a camera); H.264 needs GStreamer's x264 or
   openh264 encoder (`gstreamer1.0-plugins-ugly` or `-bad`, which the deb
   and rpm recommend). Neither has been tried with a real camera. Where the
   web view can't capture or encode, the camera turns off and the call
   stays voice-only from that side; it still shows the other side's video.
8. Shown when nobody is looking: the window isn't focused, the app is in
   the background, or (Android) it was swiped away. Tested on the Android
   emulator. Android uses its own notification from `MycelService`; the
   others use Tauri's notification plugin.

"Not yet" means the app builds and runs there without that feature.

The on-screen keyboard: on Android the page shrinks above it and the tab bar
hides. iOS slides the page under the keyboard instead of shrinking it, so the
app sizes itself to the visible part and moves there. Both are tested: Android
by hand on the emulator, iPhone with a UI test on the Simulator's on-screen
keyboard (below).

## Building

All of these run on a Mac except Linux and Windows, which build on GitHub
Actions (`.github/workflows/apps.yml`, on every push to `main` or
`platforms`, and on demand). Each run attaches the installers as artifacts:

```sh
gh run list --workflow Apps
gh run download <run-id> --dir dist-release/ci
```

### macOS

`scripts/package-mac.sh --universal` builds `dist-release/Mycel_<v>_universal.dmg`.
See [TWO_LAPTOPS.md](TWO_LAPTOPS.md) for opening an unsigned app.

### iPhone and iPad

One app for both (`TARGETED_DEVICE_FAMILY = 1,2`), iOS 16.4 or later. Needs
Xcode, rustup's `llvm-tools` component (the script adds it), and for devices
an Apple ID signed in to Xcode for the team in `tauri.conf.json`
(`bundle > iOS > developmentTeam`).

```sh
scripts/package-ios.sh --simulator   # dist-release/ios-simulator/Mycel.app
scripts/package-ios.sh               # dist-release/Mycel_<v>_ios.ipa (development-signed)
scripts/package-ios.sh --install     # ...and install it on the connected iPhone/iPad
```

**TestFlight:** `scripts/package-ios.sh --testflight N` archives with build
number N (it must be higher than the last upload) and opens the archive in
Xcode's Organizer: Distribute App > TestFlight Internal Only > Distribute.
The upload has to go through the Organizer: Xcode 27's account sign-in
(Settings > Apple Accounts) doesn't reach command-line `xcodebuild`, so
the command line can only sign with profiles Xcode already made. App Store
Connect needs the app record for `dev.mycel.host` (Xcode offers to create
it, or create it at appstoreconnect.apple.com), and asks about encryption
(export compliance) before testers can install a build.
`gen/apple/PrivacyInfo.xcprivacy` is Apple's privacy manifest; the app icons
must have no alpha channel.

On the device, the first launch needs Settings > General > VPN & Device
Management > trust the developer. With a free Apple ID the app expires after 7
days; reinstall it. Sharing it with other people needs a paid developer
account (TestFlight or ad hoc).

The Xcode project is `apps/host/src-tauri/gen/apple`, generated by
`cargo tauri ios init` and then edited: `project.yml` (frameworks the Rust
code needs, since a static library carries no link flags) is the source for
`mycel-host.xcodeproj`. Regenerate it with `xcodegen generate` in that folder
(with `Externals/` empty, or the Rust library gets bundled as a resource).
Extra Info.plist keys live in `apps/host/src-tauri/Info.ios.plist`.

### Android

Android 9 (API 28) or later; one APK for phones, tablets, Chromebooks and
emulators (arm64, armv7, x86_64). Needs a JDK 17, the Android SDK and NDK.

```sh
scripts/package-android.sh           # dist-release/Mycel_<v>_android.apk, signed
scripts/package-android.sh --debug   # quick arm64 debug build
adb install -r dist-release/Mycel_<v>_android.apk
```

Release APKs are signed with a key the script makes once in
`~/.mycel-signing/android/`. **Back that folder up**: phones only accept an
update signed with the same key. To install without adb, copy the APK to the
phone and open it (allow "Install unknown apps" for the app you open it from).

The Gradle project is `apps/host/src-tauri/gen/android` (from
`cargo tauri android init`, then edited): `MainActivity.kt` (multicast lock,
system-bar and keyboard insets for the page, "Open with", a window for a
reopened activity), `MycelService.kt` (the foreground service and
notifications), `AndroidManifest.xml` (permissions) and
`app/build.gradle.kts` (signing). Tauri's Android IPC can't carry raw bytes,
so files and video frames cross it as base64 (`invokeBytes` in the SDK).

### Windows

Windows 10 or later. The CI job builds an NSIS installer (`Mycel_<v>_x64-setup.exe`)
and an MSI. Both are unsigned, so SmartScreen warns: More info > Run anyway.
Windows Firewall asks the first time Mycel listens; allow private networks for
LAN discovery. Video calls need the camera allowed for desktop apps
(Settings > Privacy & security > Camera). To build on a Windows machine:
`npm install && cd apps/host && cargo tauri build`.

### Linux

The CI job builds a `.deb`, an `.rpm` and an `.AppImage` on Ubuntu 22.04
(glibc 2.35 or newer). To build on Linux, install the libraries listed in the
workflow (`libwebkit2gtk-4.1-dev`, `libdbus-1-dev`, `libasound2-dev`, …) and run
`cargo tauri build` in `apps/host`.

## Testing on simulators

- **iOS Simulator:** `xcrun simctl install booted dist-release/ios-simulator/Mycel.app`.
  The Simulator shares the Mac's network, so it finds Macs and other
  simulators on the LAN.
- **Android emulator:** `adb install -r <apk>`. The emulator is behind its own
  NAT (10.0.2.x): it reaches other devices over the internet paths, not mDNS.
  Debug builds can be driven from Chrome DevTools: forward
  `localabstract:webview_devtools_remote_<pid>` with `adb forward` and evaluate
  `window.__TAURI_INTERNALS__.invoke(...)` in the page.
- **A desktop peer to talk to:** `mycel serve --data /tmp/peer --http 127.0.0.1:7788`,
  then `mycel call <command> '<json>' --http 127.0.0.1:7788 --data /tmp/peer`.
  `MYCEL_AUDIO=test MYCEL_VIDEO=test` give it a tone and a test pattern
  instead of the Mac's microphone and camera.
- **Android settings:** apps get no environment variables, so
  `adb shell setprop debug.mycel.<name> <value>` stands in for `MYCEL_<NAME>`
  (`audio`, `video_debug`, `net`, `links`, `mesh`, `ble_log`), read when the
  app starts.
- **iPhone UI test:** `apps/host/ios-uitests` drives the installed app with
  XCUITest: it opens a conversation, types on the on-screen keyboard and
  checks the header and composer stay in view. It needs a conversation with
  a contact (default "Desk Test", or set `TEST_RUNNER_MYCEL_CONTACT`):

  ```sh
  cd apps/host/ios-uitests && xcodegen generate
  xcodebuild test -project MycelUITests.xcodeproj -scheme MycelUITests \
    -destination 'platform=iOS Simulator,name=iPhone 18 Pro'
  ```

## Platform notes for contributors

- `libc` is held below 0.2.190 (`apps/host/src-tauri/Cargo.toml`): 0.2.190
  declares Apple routing-socket items for macOS only, which breaks Iroh's
  `netwatch` and `netdev` on iOS.
- `vendor/swift-rs` fixes linking Tauri's Swift code with Xcode 27
  (`vendor/swift-rs/MYCEL_PATCH.md`).
- The host window opens only after the runtime is ready (`"create": false` in
  `tauri.conf.json`, built in `setup`): phones load the page faster than the
  runtime opens.
- Safe areas: the page pads itself with `--safe-*` (theme.css), from
  `env(safe-area-inset-*)` on iOS and from `MainActivity`'s inset reports on
  Android.
