# Mycel on every platform

One codebase, five apps: the Tauri host (`apps/host`) with the Rust runtime
(`crates/mycel-node`) inside, built for macOS, iPhone and iPad, Android, Windows
and Linux. The UI is the same web UI everywhere; under 720 px wide it switches
to the phone layout (tab bar at the bottom).

**Run the same build on every device when you can.** Since wire version 2
([PROTOCOL.md](PROTOCOL.md)) builds negotiate the protocol version. The
`dev-2026-10-09-apps` release speaks the same wire format (version 1) and
passed a basic cross-build check, but it validates some data differently
from newer builds, so it may still produce data a newer build refuses
(PROTOCOL.md §5). Older pre-release builds changed formats unannounced.
The chat rules are still built in, so a space's devices should share
them.

Installing, permissions, logs and troubleshooting: [USER_GUIDE.md](USER_GUIDE.md).

## What works where

| | macOS | iPhone / iPad | Android | Windows | Linux |
|---|---|---|---|---|---|
| Messages, groups, files of any size | yes | yes | yes | yes | yes |
| Same Wi-Fi / LAN discovery | mDNS | Bonjour¹ | mDNS² | mDNS | mDNS |
| Internet (relays, hole punching, DHT lookup) | yes | yes | yes | yes | yes |
| Mesh routing and store-and-forward through other devices | yes | yes | yes | yes | yes |
| Peer-to-peer Wi-Fi with no network (AWDL) | yes¹⁰ | yes¹⁰ | no | no | Wi-Fi Direct groups, off by default¹⁰ |
| Bluetooth LE link | yes | yes³ | no | no | BlueZ¹⁰ |
| Other network interfaces as their own paths⁴ | yes | yes | yes | no | yes |
| Voice calls | echo cancelled | echo cancelled | echo cancelled⁵ | no echo cancellation⁶ | no echo cancellation⁶ |
| Sending video | yes | yes, camera untested on a device³ | yes⁸ | yes⁸ | yes, with GStreamer's H.264 encoders⁸ |
| Opening a received file | default app | share sheet | "Open with" | default app | default app |
| Keeps running in the background | yes | slow mode⁷ | yes⁷ | yes | yes |
| Notifications (new messages, incoming calls)⁹ | yes | yes, while running⁷ | yes | yes | yes |

**How each was tested:**
- **macOS:** the full Rust test suite; the app on real Macs, on the LAN and
  over Bluetooth to an iPhone. Peer-to-peer Wi-Fi only on emulated links
  and on one Mac.
- **iPhone and iPad:** the iOS Simulator (iPhone and iPad layouts, an
  XCUITest for the on-screen keyboard), and a real iPhone: LAN discovery
  through Bonjour, and Bluetooth links to Macs.
- **Android:** the Android 14 emulator, through the real UI: messages both
  ways, the on-screen keyboard, attachments both ways, notifications,
  running in the background and after being swiped away, and video calls
  both ways. Not on a physical phone.
- **Windows and Linux:** GitHub Actions runners only: the core tests, a
  launch test (the runtime opens and the UI renders in WebView2 /
  WebKitGTK), and a video probe without a camera. Neither app has run on a
  desktop machine or with a real camera, and Linux's Bluetooth and Wi-Fi
  Direct code has been compiled and tested on emulated links only.

1. iOS uses the system's Bonjour (no multicast entitlement needed); the other
   platforms run Iroh's mDNS, and a patched `swarm-discovery`
   (`vendor/swarm-discovery/MYCEL_PATCH.md`) lets the two see each other.
   iOS asks for Local Network access the first time; without it, only
   internet paths work.
2. `MainActivity` holds a Wi-Fi multicast lock so mDNS packets get through.
3. The Mac code (Network.framework, CoreBluetooth, AVFoundation and
   VideoToolbox) runs on iOS too, with the front camera and upright frames
   for a phone held in portrait. Bluetooth has run between a real iPhone and
   Macs; the camera and peer-to-peer Wi-Fi haven't run on a device (the
   Simulator has no camera and no radios: Bluetooth reports "Unsupported"
   and the app carries on). iOS only allows these in the foreground.
4. `crates/mycel-link-iface`: a cable between two computers, a second NIC, or
   any interface with only link-local addresses becomes a path of its own.
   Windows has no interface link. Tested on macOS (loopback and Wi-Fi/Ethernet
   interfaces on one Mac).
5. AAudio's voice-communication input preset (`crates/mycel-call/src/android.rs`).
6. Plain devices through `cpal`: use headphones, or the far end hears itself.
7. See [Background delivery without a server](#background-delivery-without-a-server).
   **Android:** a foreground service (`MycelService`, a quiet "Mycel is
   connected" notification) keeps the runtime running with the app in the
   background or swiped away from recents, and starts again after a reboot
   or an update. **iPhone and iPad:** slow mode. iOS suspends apps; Mycel
   catches up when iOS lends it time and over Bluetooth, and new messages
   may wait until it's opened. Calls carry on in the background.
8. Android, Windows and Linux have no VideoToolbox, so the web view captures
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
   and rpm recommend). Where the web view can't capture or encode, the
   camera turns off and the call stays voice-only from that side; it still
   shows the other side's video.
9. Shown when nobody is looking: the window isn't focused, the app is in
   the background, or (Android) it was swiped away. Tested on the Android
   emulator. Android uses its own notification from `MycelService`; the
   others use Tauri's notification plugin. On iPhone and iPad a tap opens
   the conversation it is about. Notifications say only what happened ("New
   message", "Incoming call"), never names or text.
10. Built and tested on emulated links; not tested between real devices.
    Peer-to-peer Wi-Fi is Apple's AWDL (what AirDrop uses), through
    Network.framework: two Macs, iPhones or iPads with Wi-Fi switched on,
    and no shared network. On Linux, Bluetooth uses BlueZ and is
    wire-compatible with the Apple code, so a Linux machine and a Mac can
    link. Linux forms Wi-Fi Direct groups with other Mycel devices only when
    turned on (`MYCEL_WIFI_DIRECT=1` or `MYCEL_LINKS=all,wifidirect`), since
    it takes over the radio's P2P side; it needs wpa_supplicant with D-Bus.
    See [USER_GUIDE.md](USER_GUIDE.md) §6 for trying them.

The on-screen keyboard: on Android the page shrinks above it and the tab bar
hides. iOS slides the page under the keyboard instead of shrinking it, so the
app sizes itself to the visible part and moves there. Both are tested: Android
by hand on the emulator, iPhone with a UI test on the Simulator's on-screen
keyboard (below).

## Background delivery without a server

Mycel has no push server, so nothing can wake a phone the moment a message
is sent. Messages wait on the sender (and on keepers and store-and-forward
carriers) until the recipient's device is reachable. What each phone does
to be reachable as often as it can, and how honestly the app says so:

### Android: stay connected

- **`MycelService`** is a foreground service of type `connectedDevice`
  ("interaction with external devices over Bluetooth, NFC, IR, USB, or
  network"): it keeps the runtime's connections to other devices running
  Mycel open: phones and computers on the same Wi-Fi or LAN, found by mDNS,
  and those reached through them. Mycel has no Bluetooth link on Android
  yet (no backend, no Bluetooth permissions), so the case rests on network
  devices only, and keeping internet connections open is not by itself
  "interaction with external devices". Not `dataSync`, which Android 15
  caps at 6 hours a day and forbids starting after a reboot. Its
  prerequisite is a Wi-Fi or network permission in the manifest
  (`CHANGE_WIFI_MULTICAST_STATE`, `CHANGE_NETWORK_STATE`; no prompt).
- **Google Play declaration (draft, not submitted or reviewed).** Play asks
  apps targeting Android 14+ to justify each foreground service type. The
  text Mycel would give for `connectedDevice`:

  > Mycel is a peer-to-peer messenger with no server. The foreground
  > service keeps open the encrypted connections to the user's other
  > devices and contacts' devices running Mycel on the same Wi-Fi or local
  > network, which it finds by mDNS and exchanges messages and calls with
  > directly. Without it, messages from those devices can't reach the
  > phone while the app is in the background, since there is no push
  > server to wake it. The user sees a silent, persistent notification and
  > can stop it by force-stopping the app.

  If Play rejects that, the fallback is `specialUse` with a
  `PROPERTY_SPECIAL_USE_FGS_SUBTYPE` property saying the same
  ("peer-to-peer messaging without a push server"), which Play reviews case
  by case.
- **No window needed.** Tauri opens the runtime when the first activity is
  created, so the service now opens the same runtime itself when there is
  no activity (`MycelRuntime.kt`, `src-tauri/src/android.rs`), for an
  existing profile only, and a window opened later adopts it. That makes
  three restarts possible:
  - after a reboot or an update (`BootReceiver`: `BOOT_COMPLETED` and
    `MY_PACKAGE_REPLACED`, both allowed to start a foreground service on
    Android 12+; Android doesn't deliver them to an app that was never
    opened or was force-stopped);
  - after Android kills the process (`START_STICKY`). Android 12+ may
    refuse to make a restarted service foreground (Mycel not exempt from
    battery optimisation, and not recently in use), and ignores the request
    silently when the user restricted background use in Settings (the
    service asks Android whether it took). Then it catches up once (at most
    45 s) and stops, unless the app started it again meanwhile: a late
    catch-up never stops the service a newer start made foreground;
  - a periodic backstop (`CatchUpWorker`, WorkManager, every 3 hours when
    the system allows): restart the service if allowed, else one 60 s
    catch-up. Android 16 holds jobs to runtime quotas per standby bucket,
    so this stays short and occasional, never the delivery path.
- **Battery optimisation.** The Profile panel's *In the background* card
  says whether Mycel may run unrestricted and, only while it may not,
  explains why it asks (no push server; costs some battery; reversible)
  before offering the system prompt
  (`ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`, which Play allows for apps
  that can't use push). It also flags a user restriction in Settings or the
  "restricted" standby bucket, and gives a tip for vendors whose battery
  managers stop apps regardless (Samsung, Xiaomi, Huawei/Honor,
  OnePlus/OPPO/realme). The full guide is in [USER_GUIDE.md](USER_GUIDE.md#keeping-mycel-running-on-android).
- **Notifications** carry one fixed sentence per kind ("New message"), never
  names or text, also when they come from a background start. There is no
  opt-in for previews.

### iPhone and iPad: slow mode

- **App refresh and processing.** `main.mm` registers two `BGTaskScheduler`
  tasks before launch finishes (`dev.mycel.refresh`, 25 s;
  `dev.mycel.processing`, up to 120 s). Each launch asks for the next one of
  its own kind, and leaving the app asks only for kinds not queued already
  (asking again replaces a queued request and its earliest date, which
  would keep the processing task an hour away for an app left often). Each
  catch-up syncs every conversation with every member at once (keepers and
  reachable peers first, peers in failure backoff skipped), then lingers up
  to 10 s for deliveries from keepers and carriers, stopping 3 s before its
  budget ends, and saves (`src-tauri/src/background.rs`); iOS's
  expiration handler stops it early. A member who is asleep costs one 6 s
  connect timeout for the whole catch-up, not one per conversation: one
  sleeping member in six conversations measured 6.0 s (36.0 s before; the
  `mycel-net` test `a_sleeping_member_costs_one_connect_timeout_not_one_per_conversation`,
  loopback). A member that connects and then stalls holds up only its own
  syncs (unless it shares more conversations than the node's 16 sync
  slots, which it can then fill until its replies time out); whatever the
  budget cuts short waits for the next catch-up, and such a catch-up isn't
  shown as the last check.
  iOS decides when they run: typically a few times a day for an app used
  regularly, more while charging; never after the user swipes Mycel away
  in the app switcher, until it's opened again.
- **Bluetooth in the background.** The `bluetooth-central` background mode
  keeps scanning (always filtered by Mycel's service, as iOS requires in
  the background) and dialing devices that advertise Mycel (computers, and
  phones with Mycel open), and CoreBluetooth events wake Mycel briefly;
  while awake, its LAN and peer-to-peer Wi-Fi paths run too. While Mycel is
  in the background (also when iOS launched it straight there) it **links
  only with known devices**: contacts and members of its conversations. An
  unknown advertiser's key is read and the iPhone hangs up without sending
  its own; channels to strangers close when the app leaves the
  foreground. So a locked iPhone doesn't relay for strangers over
  Bluetooth, and never hands its key to one that merely advertises Mycel. The central
  opts into **state restoration**: iOS relaunches Mycel in the background
  for a Bluetooth event after ending it for memory (not after a swipe
  away). **Not `bluetooth-peripheral`:** with it, a locked iPhone would keep
  advertising and serving the readable characteristic that carries its
  long-term device key to anyone in range, all day (a tracking beacon). So
  two iPhones that both have Mycel in the background don't find each other
  over Bluetooth; one of them has to be open. What the Bluetooth link
  reveals, and the fix that would allow background advertising, are in
  [TRUST.md](TRUST.md#8b-mesh-relays-what-they-can-and-cant-do) (§8b, known limits). Neither
  the characteristic nor the channel's hello carries the display name
  (nearby devices read it from the signed contact card, encrypted), so a
  device seen only over Bluetooth shows in *Nearby* by its short ID until
  it's added or found on the LAN.
- **The grace period.** Leaving the app still asks for iOS's usual
  background time so sends finish.
- **What the app says.** The *In the background* card says "Slow mode: new
  messages may wait until you open Mycel", why (no push server), what does
  wake it, that swiping it away stops the checks, and when the last
  background check ran. Notifications are local, one fixed sentence each.
  A launch straight into the background starts as "nobody looking", so an
  incoming call during a catch-up shows its notification.
- **The optional wake relay** for timely delivery is a design only, off by
  default if it is ever built: [WAKE_RELAY.md](WAKE_RELAY.md), with its
  trust in [TRUST.md](TRUST.md#8e-optional-wake-relay-designed-not-built).

### What the platforms allow (researched 2026-10)

- **iOS has no server-free timely wake.** `BGAppRefreshTask` and
  `BGProcessingTask` run when iOS chooses. iOS 26's
  `BGContinuedProcessingTask` is for work the user starts, with visible
  progress, not sync. PushKit VoIP pushes must report a real CallKit call
  or iOS terminates the app. Local Push Connectivity needs an entitlement
  and runs only on configured Wi-Fi networks, against "your server".
  Bluetooth state restoration doesn't survive a force-quit.
- **Wi-Fi Aware (iOS 26)** gives secure, fast peer-to-peer links to
  *paired* devices (pairing through DeviceDiscoveryUI or AccessorySetupKit,
  the `com.apple.developer.wifi-aware` entitlement, iPhone 12 or later).
  Apple's documentation: apps "may connect to paired Wi-Fi Aware devices
  whenever [they're] running, in both foreground and background states",
  getting runtime "using any of the existing mechanisms", such as
  BackgroundTasks. So it doesn't wake a suspended app. The EU's DMA decision
  requires Apple to interoperate with Android's Wi-Fi Aware, but early
  reports of iOS–Android pairing failures exist. Mycel doesn't use it yet;
  it would be a fast local path during a catch-up or a Bluetooth wake, and
  needs a pairing step Mycel doesn't have.
- **iOS 27:** no primary source found for a new background or wake
  mechanism. A secondary source describes long-running App Intents, which
  are user-started with visible progress: not a wake.
- **Android:** Android 14+ requires a declared type; Android 15 caps
  `dataSync` and `mediaProcessing` and bars some types from boot receivers
  (`connectedDevice` isn't one); Android 16 puts jobs under runtime quotas,
  also alongside a foreground service; Android 17's confirmed change is to
  background audio. Vendors (Samsung, Xiaomi, Huawei, OnePlus and others)
  stop apps beyond what Android requires, which only users can undo.

### How it was tested

- **Unit tests (macOS):** the catch-up's budget, linger and cancellation
  (`background.rs`, paused tokio time); per-launch cancel tickets (a cancel
  before the catch-up begins ends it at once; one launch's cancel never
  stops another's); one catch-up at a time (also after a panic); the
  windowless lifecycle against two real runtimes on loopback (`lib.rs`: no
  profile is created without a window, an existing one opens, later opens
  adopt the same core; a message Alice wrote while Bob's profile was closed
  reaches Bob's replica through a windowless catch-up, so does one she
  pushes during the linger, and a catch-up whose sync the budget cuts short
  isn't recorded); a background launch starting "away" so a call rings;
  the sync of every conversation at once (`mycel-net` `tests/pool.rs`); the
  Kotlin status JSON mapping; that neither iOS Info.plist declares
  `bluetooth-peripheral`; the GATT payload and the hello carrying no name;
  the restricted Bluetooth mode (`mycel-link-ble` `core.rs` and the fake
  radio: a stranger is never linked, live links to strangers close, known
  devices link, lifting it links strangers again); `Runtime::known_peers`;
  the UI copy
  (`apps/host/tests/backgroundStatus.test.ts`); and `Runtime::profile_exists`.
- **JVM unit tests (Android, `gen/android/app/src/test`, `./gradlew
  :app:testArm64DebugUnitTest`):** the service's and the worker's
  decisions (`BackgroundPolicy.kt`), including the regression where a late
  catch-up stopped the service the app had just made foreground, a
  foreground start with no runtime (no profile, or a store that won't
  open) that never stopped, and a worker stopped while the runtime opens.
- **Builds and emulator checks:** [TESTING.md](TESTING.md#phones-and-the-other-platforms).
- **Not tested on real phones:** none of this has run on a physical Android
  phone or iPhone. BGTaskScheduler never runs in the Simulator, and
  Bluetooth state restoration needs a real device; vendor battery managers
  need the vendors' phones.

## Building

All of these run on a Mac except Linux and Windows, which build on GitHub
Actions (`.github/workflows/apps.yml`, on every push to `main`, on tags, and
on demand). Each run attaches the installers as artifacts:

```sh
gh run list --workflow Apps
gh run download <run-id> --dir dist-release/ci
```

Every build needs Rust (stable), Node.js 22 and the Tauri CLI
(`cargo install tauri-cli --version '^2' --locked`).

### macOS

`scripts/package-mac.sh --universal` builds `dist-release/Mycel_<v>_universal.dmg`
(without `--universal`: this Mac's architecture only). The app is unsigned;
see [USER_GUIDE.md](USER_GUIDE.md) for opening it on another Mac.

### iPhone and iPad

One app for both (`TARGETED_DEVICE_FAMILY = 1,2`), iOS 16.4 or later. Its
bundle ID is `com.atullal.mycel` (`tauri.ios.conf.json`); the other
platforms use `dev.mycel.host`. Needs Xcode, rustup's `llvm-tools`
component (the script adds it), and for devices an Apple ID signed in to
Xcode for the team in `tauri.conf.json` (`bundle > iOS > developmentTeam`).
To build with your own account, set your team there and pick a bundle ID
you own.

```sh
scripts/package-ios.sh --simulator   # dist-release/ios-simulator/Mycel.app
scripts/package-ios.sh               # dist-release/Mycel_<v>_ios.ipa (development-signed)
scripts/package-ios.sh --install     # ...and install it on the connected iPhone/iPad
scripts/package-ios.sh --unsigned    # an unsigned .ipa, for re-signing
```

**TestFlight:** `scripts/package-ios.sh --testflight N` archives with build
number N (it must be higher than the last upload) and opens the archive in
Xcode's Organizer: Distribute App > TestFlight Internal Only > Distribute.
The upload has to go through the Organizer: Xcode 27's account sign-in
(Settings > Apple Accounts) doesn't reach command-line `xcodebuild`, so
the command line can only sign with profiles Xcode already made. App Store
Connect needs an app record for the bundle ID, and asks about encryption
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
(with `Externals/` empty, or the Rust library gets bundled as a resource),
then restore `mycel-host_iOS/Info.plist` and the scheme, which xcodegen
rewrites. Extra Info.plist keys live in `apps/host/src-tauri/Info.ios.plist`
(and the merged copy in `gen/apple/mycel-host_iOS/Info.plist`).
`Sources/mycel-host/main.mm` registers the background tasks before the app
starts.

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
notifications), `MycelRuntime.kt` (the runtime with no window, battery
status), `BootReceiver.kt` and `CatchUpWorker.kt` (restarts and the
backstop), `AndroidManifest.xml` (permissions) and `app/build.gradle.kts`
(signing, WorkManager). Tauri's Android IPC can't carry raw bytes,
so files and video frames cross it as base64 (`invokeBytes` in the SDK).

### Windows

Windows 10 or later. The CI job builds an NSIS installer (`Mycel_<v>_x64-setup.exe`)
and an MSI, both unsigned. To build on a Windows machine:
`npm install && cd apps/host && cargo tauri build`.

### Linux

The CI job builds a `.deb`, an `.rpm` and an `.AppImage` on Ubuntu 22.04
(glibc 2.35 or newer). To build on Linux, install the libraries the Linux job
in `.github/workflows/apps.yml` installs (`libwebkit2gtk-4.1-dev`,
`libdbus-1-dev`, `libasound2-dev`, …) and run `cargo tauri build` in `apps/host`.

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
  (`audio`, `video_debug`, `net`, `links`, `mesh`), read when the app starts.
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
- `vendor/tauri-plugin-notification` fixes iOS notification taps after a
  restart, including a tap that launches the app
  (`vendor/tauri-plugin-notification/MYCEL_PATCH.md`).
- The host window opens only after the runtime is ready (`"create": false` in
  `tauri.conf.json`, built in `setup`): phones load the page faster than the
  runtime opens.
- The profile lock is `flock(2)` on every Unix (std's `File::try_lock` isn't
  implemented on Android) and `LockFileEx` on Windows. The identity's
  no-clobber install is `renameatx_np(RENAME_EXCL)` on Apple platforms and
  `renameat2(RENAME_NOREPLACE)` on Linux and Android 11+, else a hard link,
  else an exclusive copy (Android 10 denies links in app data; older Android
  may not allow `renameat2`). On Android the data folder is the app's data
  root, so only Mycel's own files say a profile exists.
- Backups: iOS excludes the profile folder from iCloud and computer backups;
  Android sets `allowBackup="false"` and data extraction rules
  (`res/xml/data_extraction_rules.xml`) so nothing is backed up or moved to a
  new phone. The identity is the device's own; peers sync conversations back.
- Safe areas: the page pads itself with `--safe-*` (theme.css), from
  `env(safe-area-inset-*)` on iOS and from `MainActivity`'s inset reports on
  Android.
