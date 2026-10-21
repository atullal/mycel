# Using Mycel

How to install the app, connect two or more devices, and find out what is
going on when they don't connect. No accounts and no server are involved:
devices find each other on the local network, over Bluetooth, or over the
internet by key.

> Mycel is experimental and its cryptography has not had an external
> review. Don't use it for anything that needs to stay secret yet.

What works on which platform, and how each was tested, is in
[PLATFORMS.md](PLATFORMS.md).

## 1. Install

**Use the same build on every device you test with when you can.** Builds
since wire version 2 negotiate the protocol version with each other and
with pre-release builds since the `dev-2026-10-09-apps` release
([PROTOCOL.md](PROTOCOL.md) §5), but older pre-release builds changed
formats unannounced: one can miss a
newer one's messages or not see it on the network at all.

| Device | File | First launch |
|---|---|---|
| Mac (Apple silicon and Intel) | `Mycel_<version>_universal.dmg` | Drag Mycel to Applications. The app isn't signed with an Apple developer ID, so a plain double-click is blocked: right-click (or Control-click) **Mycel > Open**, then **Open**. On recent macOS, if there is no Open button, try once, then **System Settings > Privacy & Security > Open Anyway**. If macOS says the app "is damaged", that is the quarantine flag on a downloaded unsigned app: `xattr -dr com.apple.quarantine /Applications/Mycel.app`. |
| Windows 10 or later | `Mycel_<version>_x64-setup.exe` or the `.msi` | Unsigned, so SmartScreen warns: **More info > Run anyway**. |
| Linux (glibc 2.35 or newer) | `.deb`, `.rpm` or `.AppImage` | Install the package, or make the AppImage executable and run it. For video calls, install GStreamer's x264 or openh264 encoder (`gstreamer1.0-plugins-ugly` or `-bad`); the deb and rpm recommend them. |
| Android 9 or later | `Mycel_<version>_android.apk` | Copy it to the phone and open it (allow "Install unknown apps" for the app you open it from), or `adb install -r <apk>`. |
| iPhone and iPad (iOS 16.4 or later) | build it yourself | Needs an Apple developer account in Xcode: `scripts/package-ios.sh --install` (see [PLATFORMS.md](PLATFORMS.md)). The first launch needs **Settings > General > VPN & Device Management >** trust the developer. |

To build any of these from source, see [PLATFORMS.md](PLATFORMS.md).

## 2. Allow what it asks for

Without the network permissions, devices can't see or reach each other.

- **macOS**
  - *"Allow Mycel to find devices on local networks?"* → **Allow**. Missed
    it: **System Settings > Privacy & Security > Local Network**, turn Mycel
    on, then quit and reopen Mycel.
  - *"Do you want the application Mycel to accept incoming network
    connections?"* (only with the macOS firewall on) → **Allow**. Missed it:
    **System Settings > Network > Firewall > Options…**, set Mycel to *Allow
    incoming connections*. Because the app is unsigned, macOS may ask again
    after you replace it with a new build.
  - *"Mycel would like to use Bluetooth"* → **Allow** (**Privacy & Security
    > Bluetooth**).
  - Microphone and camera are asked for on the first call (**Privacy &
    Security > Microphone / Camera**).
  - When you first attach a file from Desktop, Documents or Downloads, macOS
    may ask to let Mycel read that folder → **Allow**.
- **iPhone and iPad:** Local Network (without it, only internet paths
  work), Bluetooth, and on first use the microphone, camera and photos.
  Notifications are asked for while the app is open.
- **Android:** notifications (Android 13 and later), and the microphone and
  camera on the first call.
- **Windows:** Windows Firewall asks the first time Mycel listens; allow
  private networks for discovery on the LAN. Video calls need the camera
  allowed for desktop apps (**Settings > Privacy & security > Camera**).

## 3. Name each device

A new profile is named after the computer (on an iPhone, after the phone).
Tap your avatar (**Profile**) to change it to something the other side will
recognise. On a desktop the window title shows it too.

## 4. Add each other

- **Nearby (easiest).** Open **Nearby** (the radar button). Within a few
  seconds devices running Mycel on the same network, or in peer-to-peer
  Wi-Fi or Bluetooth range, appear by name. Click **Add**. Adding on one side is enough for that side
  to start a chat.
- **Contact codes.** On one device, **Profile > Your contact code**: copy it
  or show the QR code. On the other, **Contacts > Add by contact code**,
  paste, **Add**. A contact code holds the person's keys and name, plus the
  device's current network addresses (the part after `@`), so contact codes
  work on networks that block discovery, as long as the two devices can
  reach each other's address. If the address changes (a new network, a new
  DHCP lease), discovery or a fresh code fixes it.

**Message requests.** A chat started by someone who isn't your contact
arrives as a request. Until you **Accept**, nothing is sent back: no
profile, no read receipts, no replies, and no files are stored. Accepting
adds them to your contacts. **Decline** or **Block** (which also refuses
their future invites at the network layer) are the alternatives.

## 5. Messages and files

1. In **Messages**, start a **New conversation**, pick the other device, and
   send.
2. The mark next to your message goes from a clock (*saved on this device*)
   to ticks: *sent* (another device, such as a keeper, holds a copy),
   *delivered* (everyone in the chat has it) and *read* (everyone has opened
   the chat).
3. Replies, reactions, edits, deletes, typing indicators and group chats
   work the same way. On a desktop, hover a message for its actions,
   right-click it, or press ↑ in an empty composer to edit your last
   message. On a phone, long-press a message for its actions and swipe it to
   reply; the microphone records a voice note you can play back before
   sending.
4. **Files of any size.** Attach, drag onto the conversation, or paste.
   Folders and macOS packages (`.pages`, `.app`…) are sent as a `.zip`.
   Files up to 16 MiB are sent to everyone at once; bigger ones download
   when the other side clicks download, with a progress bar, from anyone in
   the chat who has them. An interrupted download resumes. A transfer is
   refused if it would leave less than 1 GiB of free disk.

**Delete for everyone** removes your own message from the conversation as
other devices sync (copies people saved elsewhere remain). **Delete for
me** removes any message from this device's history only, with an undo.

## 6. Paths, and no internet

The **Network** panel shows each path (same network, peer-to-peer Wi-Fi,
Bluetooth, other network interfaces, internet relay, mesh), whether it
works, and which path each person is reached by right now.

By default Mycel uses **every path** (*All paths*), including encrypted
internet relays when the internet is there. **Local only** never contacts
the internet: pick it in the Network panel and restart. None of the local
paths need the internet.

To check that it works with no internet, keep the devices on one local
network and cut the uplink: unplug the router's internet cable, use a phone
hotspot with mobile data off, or connect two computers with a cable (they
get link-local addresses, and discovery works across it). A website should
then fail to load on both.

### No shared network: peer-to-peer Wi-Fi and Bluetooth

Two devices don't need to share a network. Bluetooth has run between a real
iPhone and Macs, with far less mileage than on emulated links. **Peer-to-peer
Wi-Fi, and Linux's Bluetooth and Wi-Fi Direct, have been tested only on
emulated links, not between real devices**, so trying them on real devices
is the most useful testing there is. Watch the Network panel's *Talking to*
list say which path is used:

1. **Leave the Wi-Fi network but keep Wi-Fi on** (Macs, iPhones and iPads:
   disconnect from or forget the network; unplug Ethernet). Mycel should
   switch to **Peer-to-peer Wi-Fi**, the Apple radio link AirDrop uses, at
   Wi-Fi speed, within a few seconds. Range is roughly a room or two.
2. **Turn Wi-Fi off, keep Bluetooth on.** Mycel falls back to
   **Bluetooth**: slow (roughly 15–60 KB/s), fine for text, slow for photos,
   impractical for big files. Range is about 10 m.
3. **Turn Wi-Fi back on or rejoin the network.** Mycel moves back to the
   faster path by itself.

A transfer or call in progress moves to the next path when the current one
dies, after about 5 seconds of detecting it.

If a path doesn't come up, the Network panel's *Paths* list says why (for
example "Bluetooth is off", or a permission to allow). If peer-to-peer Wi-Fi
or Bluetooth doesn't connect between two Macs, run Mycel from Terminal with
`MYCEL_AWDL_DEBUG=1 MYCEL_BLE_LOG=2 /Applications/Mycel.app/Contents/MacOS/mycel-host`
and keep the log.

### Cables, other interfaces and Linux

Mycel uses every network interface a computer has: each becomes its own
path, shown in the *Paths* list by what it is ("Cable bridge0", "Wi-Fi
Direct p2p-wlan0-0", "UWB lowpan0", "Thread / 802.15.4 wpan0"). A faster
path wins and slower ones stay as backups.

- **A cable between two Macs** (Thunderbolt or USB-C): the Thunderbolt
  bridge gets a link-local address and becomes a *Cable* path, even with no
  network at all.
- **To see what Mycel makes of your interfaces:**
  `cargo run -p mycel-link-iface --example ifaces` (add `-- --no-ip` for what
  it does with `MYCEL_IP=0`). It only reads the interface list.
- **Say what an interface is** when its name doesn't:
  `MYCEL_IFACE_MEDIUM=wpan0=uwb,mesh0=other`. Use only some interfaces:
  `MYCEL_IFACES=lowpan0,p2p-wlan0-0`. Log what the interface link does:
  `MYCEL_IFACE_LOG=1`. Interfaces need no special permission (the link binds
  to each interface's IPv6 link-local address); interfaces with IPv6
  disabled can't be used.
- **UWB:** Macs have no UWB radio. On Linux a UWB (IEEE 802.15.4z) radio
  carries data only if its driver exposes it through the kernel's
  ieee802154 stack as a 6LoWPAN interface
  (`ip link add link wpan0 name lowpan0 type lowpan`); most UWB chips only
  do ranging.
- **Bluetooth on Linux** uses BlueZ and links with Macs too. `bluetoothd`
  must be running and your user allowed to advertise: on distributions
  whose BlueZ D-Bus policy uses the `bluetooth` group, add yourself
  (`sudo usermod -aG bluetooth $USER`, then log in again). No pairing is
  needed.
- **Wi-Fi Direct on Linux** is off by default; turn it on with
  `MYCEL_WIFI_DIRECT=1` (or `MYCEL_LINKS=all,wifidirect`). It needs
  wpa_supplicant running with D-Bus (`-u`), a Wi-Fi driver with P2P support,
  and permission to use wpa_supplicant's D-Bus API (root, or the `netdev`
  group on Debian and Ubuntu). Mycel devices find each other and form a
  group with no prompt; the group's `p2p-*` interface then shows up as a
  path. NetworkManager may also try to manage that interface.

## 7. Calls

- **Voice:** the **phone** button in a conversation's header. The other side
  sees **Accept** or **Decline**. The call bar shows the time, the path in
  use, the bitrate (32 kbps on a network or peer-to-peer Wi-Fi, 24 kbps
  through a relay or the mesh, 12 kbps over Bluetooth), a level meter for each person, **mute** and
  **hang up**. A call keeps going when its path changes, with a few seconds
  of silence if the old path died.
- **Video:** the **camera** button. The other side can accept with video,
  with voice only (turning the camera on later), or decline. Video starts
  small and sharpens within seconds: up to 720p on the same network or a
  cable, 480p over peer-to-peer Wi-Fi, 360p through a relay. Over Bluetooth or the multi-hop mesh, video
  pauses on both sides ("Video paused: slow connection") while the voice
  carries on, and comes back by itself on a faster path.
- **Groups:** the phone button rings everyone in the group; up to 8 people
  can be in a call. Each device connects to every other one directly, so
  whoever started the call can leave without ending it. Someone who
  declined or missed it can **Join call** while it lasts.
- Calling at the same moment from both sides ends in one call. A device
  that can't be reached gives *can't be reached right now* after a few
  seconds; an unanswered call gives *No answer* after 45 s on the caller and
  *Missed call* on the other side.
- Echo: macOS, iPhone and iPad use Apple's voice processing and Android its
  echo canceller, so speakers are fine. Windows and Linux have no echo
  cancellation: use headphones. If the call bar says *Use headphones to
  avoid echo*, voice processing couldn't start on that device.

## 8. Through other devices: the mesh and gateways

- **Mesh.** Two devices out of each other's range can reach each other
  through a third Mycel device between them, even one that isn't in any of
  their chats: anyone running Mycel relays by default and can't read what it
  relays. A direct path always wins, so with two devices the mesh never
  shows. With three, A and C out of range of each other and B in range of
  both, the Network panel on A shows C *via Mesh (via B, 2 hops)*.
- **Gateways.** A device with the internet is a gateway for nearby devices
  without it. A Bluetooth-only device near a gateway can be messaged and
  called from anywhere on the internet; its Network panel says *internet via*
  that gateway.
- **Carried messages.** When nobody can reach a member live, what they lack
  travels as a signed, still-encrypted bundle along whatever part of the way
  is up, toward devices with the internet, and waits at the member's
  gateway. Carriers hold at most 64 MiB for others, 4 MiB per sender, for
  up to 7 days, and learn who a bundle is for and its size, never its
  content.

How this works: [ARCHITECTURE.md](ARCHITECTURE.md) §8–9 and
[ROUTING.md](ROUTING.md).

## 9. Offline delivery and keepers

Messages wait on the sender until a recipient (or a keeper) gets them.
Quit Mycel on device B, send from A (the mark stays a clock), reopen B:
within seconds of the two finding each other the messages arrive and A's
mark moves to *delivered*.

So the sender must be running when the recipient comes back, unless a
**keeper** holds the conversation. A keeper is an always-on device that
stores encrypted copies and passes them to members. It can't read them.
On any computer with Rust and this repository:

```sh
cargo build --release -p mycel-cli
./target/release/mycel keeper --data ~/.mycel-keeper --name "Keeper" --net lan
```

It prints a contact code. Add it as a contact, then open the conversation's
details > **Keepers** > **Add a keeper**. Only the conversation's admin can
add keepers. Now A can send while B is offline and quit; B gets the
messages from the keeper later.

A suspended iPhone or iPad doesn't receive messages until Mycel is opened
again: waking it would need Apple's push service, which needs a server.
Calls continue in the background. Android keeps Mycel running in the
background, with a quiet "Mycel is connected" notification.

## 10. Where data and logs live

| | Data folder |
|---|---|
| macOS | `~/Library/Application Support/dev.mycel.host/` |
| Windows | `%APPDATA%\dev.mycel.host\` |
| Linux | `~/.local/share/dev.mycel.host/` |
| iPhone, iPad | inside the app's container; with a development build, Xcode's **Devices and Simulators** window can download it |
| Android | the app's private data folder; with a debug build, `adb shell run-as dev.mycel.host ls` |

- `mycel.redb` holds messages, contacts and settings; received files are
  under `files/`.
- `identity.key` **is** your account: anyone with it can act as you, and
  there is no recovery if it's lost. On iPhone and iPad the key is kept in
  the Keychain instead. On iPhone, iPad and Android the data folder is kept
  out of backups: a new phone is a new identity, and peers sync
  conversations back to it.
- **Logs.** Started from Finder, the Start menu or a phone's home screen,
  Mycel writes its log to `mycel.log` in the data folder (the previous run's
  is `mycel.log.1`). Started from a terminal, it logs to the terminal: on a
  Mac, `/Applications/Mycel.app/Contents/MacOS/mycel-host`.
- **More detail** (environment variables when started from a terminal):
  `MYCEL_BLE_LOG=1` (or `2`) for the Bluetooth link, `MYCEL_AWDL_DEBUG=1`
  for peer-to-peer Wi-Fi, `MYCEL_PATH_DEBUG=1`
  for every path's measurements, `MYCEL_CALL_DEBUG=1` for each call's paths,
  `MYCEL_VIDEO_DEBUG=1` for video, `MYCEL_IFACE_LOG=1` for the interface
  link. On a phone, a file named `link-diagnostics` in the data folder
  holding `1` or `2` turns on the Bluetooth log. On Android,
  `adb shell setprop debug.mycel.<name> <value>` stands in for
  `MYCEL_<NAME>`.

**Reset** (macOS; the same idea elsewhere): quit Mycel, then
`rm -rf ~/Library/Application\ Support/dev.mycel.host`. The next launch
creates a new identity, and your contacts will see a new, different person.

## 11. Several copies on one computer (for developers)

Each copy needs its own data folder; a second copy on the same folder
exits at once.

```sh
APP=/Applications/Mycel.app/Contents/MacOS/mycel-host
MYCEL_DATA_DIR=/tmp/mycel-a MYCEL_NAME="Laptop A" MYCEL_NET=lan "$APP" &
MYCEL_DATA_DIR=/tmp/mycel-b MYCEL_NAME="Laptop B" MYCEL_NET=lan "$APP" &
```

- `MYCEL_DATA_DIR`: the data folder.
- `MYCEL_NAME`: display name; replaces the saved name on every launch.
- `MYCEL_NET`: `internet` (every path, the default), `lan` (local paths
  only, never the internet) or `local` (this computer only). Overrides the
  Network panel.
- `MYCEL_LINKS`: `all` (the default), `none`, or a list of `awdl`, `ble`
  and `iface` (every other network interface); on Linux add `wifidirect` to
  form Wi-Fi Direct groups.
- `MYCEL_IP=0`: no ordinary Wi-Fi or Ethernet IP, leaving peer-to-peer
  Wi-Fi, Bluetooth and other interfaces, to show those paths work on their
  own.
- `MYCEL_MESH=0`: no multi-hop mesh. `MYCEL_MESH_RELAY=0`: use the mesh but
  relay nothing for others.

The CLI can also be a full device without the app: `mycel serve --data
~/.mycel-cli --name "Terminal" --net lan`, then open <http://127.0.0.1:7777>,
or script it with `mycel call <command> '<json>'`
([RUNTIME_API.md](RUNTIME_API.md)).

## 12. Troubleshooting

**The other device never shows up in Nearby.**
- Both must be on the **same network and subnet** (compare the first three
  numbers of their IP addresses). A device on one router's Ethernet and one
  on another router's Wi-Fi won't see each other.
- **Guest, hotel, office and campus networks** often isolate devices from
  each other and block discovery. Use a home network, a phone hotspot or a
  direct cable.
- Check the **Local Network** permission (macOS, iPhone, iPad) and the
  **firewall** (macOS, Windows, third-party firewalls). "Block all incoming
  connections" must be off.
- **VPNs** can hide the local network. Disconnect for the test.
- Wait 10 to 20 seconds: announcements are periodic. Reopening Mycel on
  both sides sends fresh ones.
- Still nothing: the network is probably blocking discovery (UDP port 5353
  multicast). **Exchange contact codes**: they carry the addresses, so the
  devices connect without discovery. If even that fails, the network blocks
  traffic between devices; switch networks.
- Check neither runs an old pre-release build: those can't see an iPhone
  running a newer one.

**Messages stuck on the clock mark or *sent*.** The other side is offline
or unreachable. In the Network panel it should show as *Connected* or *On
your network*. Messages are delivered automatically when it comes back.

**"Mycel is damaged and can't be opened"** (macOS). Gatekeeper's quarantine
on a downloaded unsigned app:
`xattr -dr com.apple.quarantine /Applications/Mycel.app`.

**A second copy exits immediately.** Only one copy can use a data folder at
a time. Use `MYCEL_DATA_DIR` for another one.

**Three LAN tests fail when you run the test suite on a Mac**
(`lan_discovery_via_mdns`, `one_path_per_interface`,
`sync_over_an_interface_with_ip_off`) with "No route to host": macOS hasn't
given your terminal Local Network access. Allow it in **System Settings >
Privacy & Security > Local Network**.

**Reporting a problem:** include the platform, how Mycel was installed, the
steps, and `mycel.log` from each device involved. Logs can hold device
names, keys and network addresses: look them over before sharing. Security
problems go through [SECURITY.md](../SECURITY.md), not public issues.
