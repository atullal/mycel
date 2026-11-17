# Mycel on every platform

This is the per-platform reference: which features run on which platform,
how each platform has been tested, and how to build each app. It is for
people who build Mycel, test it or work on its platform code.

Mycel is one codebase built as five apps. The Tauri host (`apps/host`), with
the Rust runtime (`crates/mycel-node`) inside it, is built for macOS, iPhone
and iPad, Android, Windows and Linux. The UI is the same web UI everywhere;
in a window 720 px wide or narrower it switches to the phone layout, with
the tab bar at the bottom.

**Every device must run the same build.** The wire format still changes
between builds.

Installing, permissions, logs and troubleshooting are in
[USER_GUIDE.md](USER_GUIDE.md).

## Contents

- [What works where](#what-works-where)
- [How each platform was tested](#how-each-platform-was-tested)
- [Building](#building)
- [Testing on simulators](#testing-on-simulators)
- [Platform notes for contributors](#platform-notes-for-contributors)

## What works where

| Feature | macOS | iPhone, iPad | Android | Windows | Linux |
|---|---|---|---|---|---|
| Has run on | real Macs | Simulator, one iPhone | emulator only | CI runners only | CI runners only |
| Messages, groups, files of any size | yes | yes | yes | yes | yes |
| Discovery on the same network | mDNS | Bonjour | mDNS | mDNS | mDNS |
| Internet: relays, hole punching, DHT lookup | yes | yes | yes | yes | yes |
| Mesh routing and store-and-forward | yes | yes | yes | yes | yes |
| Peer-to-peer Wi-Fi with no network | AWDL, untested on devices | AWDL, untested on devices | no | no | Wi-Fi Direct, opt-in, untested on devices |
| Bluetooth LE | yes | yes | no | no | BlueZ, untested on devices |
| Other network interfaces as paths | yes | yes | yes | no | yes |
| Voice calls | yes | yes | yes | yes | yes |
| Echo cancellation | yes | yes | yes | no | no |
| Sending video | hardware H.264 | hardware H.264, camera untested on a device | web view | web view | web view |
| Opening a received file | default app | share sheet | "Open with" | default app | default app |
| Running in the background | yes | during calls | yes | yes | yes |
| Notifications | yes | while running | yes | yes | yes |

A "yes" says the feature is built for that platform. The first row says
where the platform's app has run at all, and
[How each platform was tested](#how-each-platform-was-tested) gives the
detail. The notes below explain the rows that differ between platforms.

### Discovery on the same network

iPhone and iPad use the system's Bonjour, which needs no multicast
entitlement. The other platforms run Iroh's mDNS, and a patched
`swarm-discovery` (`vendor/swarm-discovery/MYCEL_PATCH.md`) lets the two see
each other.

iOS asks for Local Network access the first time. Without it, only internet
paths work. On Android, `MainActivity` holds a Wi-Fi multicast lock so that
mDNS packets get through.

### Peer-to-peer Wi-Fi, Bluetooth and Wi-Fi Direct

Peer-to-peer Wi-Fi is Apple's AWDL, the link AirDrop uses, through
Network.framework. It connects two Macs, iPhones or iPads that have Wi-Fi
switched on and share no network.

Bluetooth goes through CoreBluetooth on macOS and iOS and through BlueZ on
Linux. The two are wire-compatible, so a Linux machine and a Mac can link.

Linux forms Wi-Fi Direct groups with other Mycel devices only when that is
turned on, with `MYCEL_WIFI_DIRECT=1` or `MYCEL_LINKS=all,wifidirect`,
because it takes over the radio's P2P side. It needs wpa_supplicant with
D-Bus.

The Mac's code for these links runs on iPhone and iPad too. iOS allows them
only while the app is in the foreground.

Bluetooth has run between a real iPhone and Macs. Peer-to-peer Wi-Fi,
Bluetooth on Linux and Wi-Fi Direct are built and tested on emulated links
and have not been tested between real devices. The iOS Simulator has no
radios: Bluetooth reports "Unsupported" there and the app carries on.
[USER_GUIDE.md](USER_GUIDE.md) says how to try these links on real devices.

### Other network interfaces

`crates/mycel-link-iface` makes a path of its own out of a cable between two
computers, a second network card, or any interface that has only link-local
addresses. Windows has no interface link.

It has been tested on macOS only, with the loopback, Wi-Fi and Ethernet
interfaces of one Mac.

### Echo cancellation

macOS, iPhone and iPad use Apple's voice processing. Android uses AAudio's
voice-communication input preset (`crates/mycel-call/src/android.rs`).

Windows and Linux use plain audio devices through `cpal`, with no echo
cancellation: use headphones, or the far end hears itself.

### Sending video

macOS, iPhone and iPad capture with AVFoundation and encode H.264 in
hardware with VideoToolbox. An iPhone or iPad uses the front camera and
turns the frames upright for a device held in portrait. Like the radio
links, the camera is allowed only while the app is in the foreground. The
iPhone camera has not run on a real device, and the Simulator has none.

Android, Windows and Linux have no VideoToolbox. There the web view captures
the camera (`getUserMedia`) and encodes H.264 with WebCodecs, in hardware
where the platform has it, and the runtime sends those frames as it sends a
Mac's (`crates/mycel-video/src/web.rs`, `packages/sdk/src/webcam.ts`).

On Linux the app turns on WebKitGTK's camera capture and encodes through a
canvas, because WebKitGTK fails on frames taken straight from a camera.
H.264 also needs GStreamer's x264 or openh264 encoder: the `.deb` recommends
`gstreamer1.0-plugins-bad` and `gstreamer1.0-plugins-ugly`, and the `.rpm`
recommends `gstreamer1-plugin-openh264`.

Where the web view cannot capture or encode, the camera turns off and the
call stays voice-only from that side. It still shows the other side's
video.

### Running in the background

On Android, a foreground service (`MycelService`, with a quiet "Mycel is
connected" notification) keeps the runtime running while the app is in the
background or has been swiped away from recents. Opening the app again gives
a new window on the same runtime.

iOS suspends apps. Calls carry on in the background (background audio), and
on going to the background the app asks iOS for its usual grace period so
that sends finish. After that, messages arrive when Mycel is opened again,
from their senders, from a keeper, or from devices that carried them
(store-and-forward). Waking a suspended iPhone needs Apple's push service,
which needs a server, and Mycel has none.

### Notifications

A notification is shown when nobody is looking: the window is not focused,
the app is in the background, or, on Android, it was swiped away. It says
only what happened ("New message", "Incoming call"), never a name or any
text.

Android posts its own notification from `MycelService`. The other platforms
use Tauri's notification plugin. On iPhone and iPad, a tap opens the
conversation the notification is about.

### The on-screen keyboard

On Android the page shrinks above the keyboard and the tab bar hides. iOS
slides the page under the keyboard instead of shrinking it, so the app sizes
itself to the visible part and moves there.

Both are tested: Android by hand on the emulator, and iPhone with a
[UI test](#iphone-ui-test) on the Simulator's on-screen keyboard.

## How each platform was tested

| Platform | Real hardware | Simulator or emulator | GitHub Actions |
|---|---|---|---|
| macOS | Macs, and an iPhone as the Bluetooth peer | none | core tests |
| iPhone and iPad | one iPhone | iOS Simulator | none |
| Android | none | Android 14 emulator | none |
| Windows | none | none | core tests, app launch, video probe |
| Linux | none | none | core tests, app launch, video probe |

On macOS, the full Rust test suite runs, and the app has run on real Macs,
on the LAN and over Bluetooth to an iPhone. Peer-to-peer Wi-Fi has run only
on emulated links and on one Mac.

On iPhone and iPad, the app has run in the iOS Simulator, in the iPhone and
the iPad layout, with an XCUITest for the on-screen keyboard. On a real
iPhone, LAN discovery through Bonjour and Bluetooth links to Macs have run.
Peer-to-peer Wi-Fi and the camera have not run on a device.

On Android, the app has run on the Android 14 emulator, through the real UI:
messages both ways, the on-screen keyboard, attachments both ways,
notifications, running in the background and after being swiped away, and
video calls both ways against a desktop peer. It has not run on a physical
phone.

Windows and Linux have run on GitHub Actions runners only. There the core
tests run, a launch test shows that the runtime opens and the UI renders
(in WebView2 and in WebKitGTK), and a video probe captures and encodes
without a camera: headless Edge, the engine under WebView2, with Chromium's
fake camera, and WebKitGTK with WebKit's mock camera
(`scripts/ci/video-probe.html`). Neither app has run on a desktop machine or
with a real camera. The Bluetooth and Wi-Fi Direct code for Linux has been
compiled and tested on emulated links only.

The results are in [TESTING.md](TESTING.md).

## Building

The macOS, iPhone and iPad, and Android apps are built on a Mac, each by a
script in `scripts/`. The Windows and Linux apps are built by
[GitHub Actions](#builds-from-github-actions), or on their own platform with
`cargo tauri build`. The scripts put their output in `dist-release/`.

Every build needs:

- Rust. rustup installs the toolchain pinned in `rust-toolchain.toml` on
  first use, and the scripts add the platform targets they need.
- Node.js 22.18 or later.
- The Tauri CLI: `cargo install tauri-cli --version '^2' --locked`.

Each script takes one option at most, and `--help` prints its usage. Each
runs `npm ci` if `node_modules` is missing, and sources
`scripts/remap-paths.sh`, which keeps the build machine's paths out of the
binaries.

### macOS

macOS 11 or later. Building needs the Xcode Command Line Tools.

```sh
scripts/package-mac.sh --universal   # one app for Apple silicon and Intel
scripts/package-mac.sh               # this Mac's architecture only
```

`--universal` builds `dist-release/Mycel_<v>_universal_notarized.dmg`, the same app as
`Mycel_<v>_universal_notarized.app.zip`, and the unpacked app in
`dist-release/universal/`. Without the option, `aarch64` or `x64` takes the
place of `universal` in those names.

Public packaging requires a Developer ID Application certificate and notarization
credentials. Missing credentials stop the build before compilation. Local
development with `cargo tauri dev` does not need release credentials.

#### Signing the Mac app

A build signed with a Developer ID and notarised by Apple opens on any Mac
without a warning. It needs membership of the Apple Developer Program and a
*Developer ID Application* certificate (an *Apple Development* certificate
will not do). With the certificate in your keychain:

```sh
MYCEL_SIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)" \
MYCEL_NOTARY_PROFILE=mycel \
  scripts/package-mac.sh --universal
```

`MYCEL_NOTARY_PROFILE` names credentials saved once with
`xcrun notarytool store-credentials`. The script signs the app with the
hardened runtime and the entitlements the microphone and camera need, has
Apple notarise it, staples the ticket to the app so that it also opens on a
Mac that is offline, and does the same for the disk image. Its header lists
the other ways to give it credentials. `scripts/verify-mac.sh` checks the
Developer ID certificate type and team, secure timestamp, hardened runtime,
stapled ticket and Gatekeeper assessment. Packaging checks both the extracted
ZIP and the app mounted from the final DMG before exposing release files.
The `_notarized` filenames are reserved for these verified outputs; the
website excludes older unsigned DMGs.

The Apps workflow does this on GitHub when the repository has these secrets:

| Secret | What it holds |
|---|---|
| `APPLE_CERTIFICATE` | the certificate and its private key, exported from Keychain Access as a `.p12` and base64-encoded (`base64 -i certificate.p12`) |
| `APPLE_CERTIFICATE_PASSWORD` | the password given when exporting the `.p12` |
| `APPLE_API_KEY_P8`, `APPLE_API_KEY_ID`, `APPLE_API_ISSUER` | an App Store Connect API key, for notarisation |
| `APPLE_ID`, `APPLE_APP_PASSWORD`, `APPLE_TEAM_ID` | an Apple ID with an app-specific password, in place of the API key |

Without the certificate or complete notarization credentials, the Mac job
fails and the release job cannot publish. There is no unsigned fallback,
including for development prereleases. Only packages that pass every check
are uploaded, checksummed and attested. Tagged public Mac releases use fresh
GitHub-hosted runners; `MACOS_RUNNER=self-hosted` applies only to non-tag
development builds. npm and Cargo use the committed lockfiles.

To create the certificate, the Apple Developer Account Holder uploads a
certificate signing request at [Certificates, Identifiers & Profiles](https://developer.apple.com/account/resources/certificates/add),
selecting **Developer ID Application** (not Apple Development or Apple
Distribution). Install the downloaded certificate with its matching private
key in Keychain Access, then export both as a password-protected `.p12`
for `APPLE_CERTIFICATE`. Keep keys and passwords outside the repository.
Notarization additionally needs one of the credential sets in the table.
The first live release still needs to be verified with the issued certificate.

### iPhone and iPad

One app for both (`TARGETED_DEVICE_FAMILY = 1,2`), for iOS 16.4 or later.
Its bundle ID is `com.atullal.mycel` (`tauri.ios.conf.json`); the other
platforms use `dev.mycel.host`.

Building needs Xcode and rustup's `llvm-tools` component, which the script
adds. A build for a device also needs Xcode signed in to the Apple
development team named in `tauri.conf.json`
(`bundle > iOS > developmentTeam`). To build with your own account, set your
team there and pick a bundle ID you own.

```sh
scripts/package-ios.sh               # dist-release/Mycel_<v>_ios.ipa, development-signed
scripts/package-ios.sh --install     # the same, then install it on a connected device
scripts/package-ios.sh --simulator   # dist-release/ios-simulator/Mycel.app, unsigned
scripts/package-ios.sh --unsigned    # dist-release/Mycel_<v>_ios-unsigned.ipa, for re-signing
scripts/package-ios.sh --testflight N   # archive with build number N for TestFlight
```

`--install` picks the first connected iPhone or iPad; a device name after
the option picks another. The Simulator build is for Apple silicon
Macs (`aarch64-sim`).

On the device, the first launch needs *Settings > General > VPN & Device
Management*, where you trust the developer. With a free Apple ID the app
runs for 7 days, and only on devices connected to the Mac that built it;
reinstall it after that. Sharing the app with other people needs a paid
developer account (TestFlight or ad hoc distribution).

#### TestFlight

`--testflight N` archives the app with build number N, which must be higher
than the last upload, and opens the archive in Xcode's Organizer. There,
choose *Distribute App > TestFlight Internal Only > Distribute*.

The upload has to go through the Organizer. Xcode 27's account sign-in
(*Settings > Apple Accounts*) does not reach command-line `xcodebuild`, so
the command line can sign only with profiles that Xcode has already made.

App Store Connect needs an app record for the bundle ID, and asks about
encryption (export compliance) before testers can install a build.
`gen/apple/PrivacyInfo.xcprivacy` is Apple's privacy manifest. The app icons
must have no alpha channel.

#### The Xcode project

The Xcode project is `apps/host/src-tauri/gen/apple`, generated by
`cargo tauri ios init` and then edited. `project.yml` is the source for
`mycel-host.xcodeproj`. It lists the frameworks the Rust code needs, because
a static library carries no link flags.

Regenerate the project with `xcodegen generate` in that folder, with
`Externals/` empty; otherwise the Rust library gets bundled as a resource.
Extra Info.plist keys live in `apps/host/src-tauri/Info.ios.plist`.

### Android

Android 9 (API 28) or later. The release build is one APK for phones,
tablets, Chromebooks and emulators (arm64, armv7 and x86_64).

Building needs JDK 17 or later and the Android SDK and NDK. The script looks
for them in the usual install locations, and `JAVA_HOME`, `ANDROID_HOME` and
`NDK_HOME` override that.

```sh
scripts/package-android.sh           # dist-release/Mycel_<v>_android.apk, signed
scripts/package-android.sh --debug   # dist-release/Mycel_<v>_android-debug.apk, arm64 only
adb install -r dist-release/Mycel_<v>_android.apk
```

The debug build is quick to make, and the app it makes is slow.

Release APKs are signed with a key that the script makes once, in
`~/.mycel-signing/android/` (`MYCEL_ANDROID_SIGNING` names another folder).
**Back that folder up.** A phone accepts an update only if it is signed with
the same key.

To install without adb, copy the APK to the phone and open it, allowing
"Install unknown apps" for the app you open it from.

The Gradle project is `apps/host/src-tauri/gen/android`, generated by
`cargo tauri android init` and then edited:

| File | What Mycel adds |
|---|---|
| `MainActivity.kt` | multicast lock, system-bar and keyboard insets for the page, "Open with", a window for a reopened activity |
| `MycelService.kt` | the foreground service and notifications |
| `AndroidManifest.xml` | permissions |
| `app/build.gradle.kts` | signing |

Tauri's Android IPC cannot carry raw bytes, so files and video frames cross
it as base64 (`invokeBytes` in the SDK).

### Windows

Windows 10 or later. The GitHub Actions job builds an NSIS installer
(`Mycel_<v>_x64-setup.exe`) and an MSI, both unsigned. To build on a Windows
machine:

```sh
npm ci
cd apps/host
cargo tauri build
```

### Linux

The GitHub Actions job builds a `.deb`, an `.rpm` and an `.AppImage` on
Ubuntu 22.04, so they need glibc 2.35 or newer.

To build on Linux, install the libraries that job installs, then build as on
Windows:

```sh
sudo apt-get install -y libwebkit2gtk-4.1-dev libgtk-3-dev \
  libayatana-appindicator3-dev librsvg2-dev libdbus-1-dev libasound2-dev \
  libssl-dev pkg-config patchelf rpm file libfuse2
npm ci
cd apps/host
cargo tauri build
```

### Builds from GitHub Actions

The Apps workflow (`.github/workflows/apps.yml`) builds the Linux, Windows
and macOS apps, and smoke-tests the first two. It runs on every push to
`main`, on tags named `dev-*` or `v*`, and on demand. Each run attaches the
installers as artifacts:

```sh
gh run list --workflow Apps
gh run download <run-id> --dir dist-release/ci
```

A tag also publishes the installers as a GitHub pre-release, with a
`SHA256SUMS` file and a build provenance attestation:

```sh
gh attestation verify <downloaded file> --repo atullal/mycel
```

The workflow does not build the iPhone and iPad or Android apps.

## Testing on simulators

### iOS Simulator

```sh
xcrun simctl install booted dist-release/ios-simulator/Mycel.app
```

The Simulator shares the Mac's network, so it finds Macs and other
simulators on the LAN.

### Android emulator

Install the APK with `adb install -r <apk>`. The emulator is behind its own
NAT (10.0.2.x), so it reaches other devices over the internet paths, not
through mDNS.

A debug build can be driven from Chrome DevTools. Forward
`localabstract:webview_devtools_remote_<pid>` with `adb forward`, and
evaluate `window.__TAURI_INTERNALS__.invoke(...)` in the page.

Android apps get no environment variables. For testing,
`adb shell setprop debug.mycel.<name> <value>` stands in for `MYCEL_<NAME>`
for six names: `audio`, `video_debug`, `net`, `links`, `mesh` and `ble_log`.
The app reads them when it starts.

### A desktop peer to test against

Run a device from the CLI, then drive it with `mycel call`:

```sh
mycel serve --data /tmp/peer --http 127.0.0.1:7788
mycel call <command> '<json>' --http 127.0.0.1:7788 --data /tmp/peer
```

Starting `mycel serve` with `MYCEL_AUDIO=test MYCEL_VIDEO=test` gives it a
tone and a test pattern in place of the microphone and the camera.

### iPhone UI test

`apps/host/ios-uitests` drives the installed app with XCUITest. It opens a
conversation, types on the on-screen keyboard, and checks that the header
and the composer stay in view.

The test needs a conversation with a contact. It reads the contact's name
from `MYCEL_CONTACT`, "Desk Test" by default; `xcodebuild` passes the
variable on when it is set as `TEST_RUNNER_MYCEL_CONTACT`.

```sh
cd apps/host/ios-uitests && xcodegen generate
xcodebuild test -project MycelUITests.xcodeproj -scheme MycelUITests \
  -destination 'platform=iOS Simulator,name=iPhone 18 Pro'
```

## Platform notes for contributors

- `libc` is held to a narrow range (`>=0.2.189, <0.2.191`) in
  `apps/host/src-tauri/Cargo.toml`. The comment beside it gives the reason:
  a `libc` release that declares Apple's routing-socket items for macOS only
  breaks Iroh's `netwatch` and `netdev` on iOS.
- `vendor/swift-rs` fixes linking Tauri's Swift code with Xcode 27
  (`vendor/swift-rs/MYCEL_PATCH.md`).
- `vendor/tauri-plugin-notification` fixes iOS notification taps after a
  restart, including a tap that launches the app
  (`vendor/tauri-plugin-notification/MYCEL_PATCH.md`).
- The host window opens only after the runtime is ready. `tauri.conf.json`
  has `"create": false`, and `setup` builds the window, because phones load
  the page faster than the runtime opens.
- The profile lock is `flock(2)` on every Unix, because std's
  `File::try_lock` is not implemented on Android, and `File::try_lock` on
  Windows.
- The identity file is installed without ever replacing an existing one:
  with `renameatx_np(RENAME_EXCL)` on Apple platforms and
  `renameat2(RENAME_NOREPLACE)` on Linux and Android 11 or later, else with
  a hard link, else with an exclusive copy. Android 10 and later deny hard
  links in app data, and Android before 11 may not allow `renameat2`.
- On Android the data folder is the app's data root, so only Mycel's own
  files say that a profile exists.
- Backups: iOS excludes the profile folder from iCloud and computer backups.
  Android sets `allowBackup="false"` and data extraction rules
  (`res/xml/data_extraction_rules.xml`), so nothing is backed up or moved to
  a new phone. The identity is the device's own, and peers sync
  conversations back.
- Safe areas: the page pads itself with `--safe-*` (`theme.css`), taken from
  `env(safe-area-inset-*)` on iOS and from `MainActivity`'s inset reports on
  Android.
