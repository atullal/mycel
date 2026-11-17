# Using Mycel

This guide is for anyone who has installed Mycel or is about to. It covers
installing the app, adding contacts, sending messages and files, making
calls, how devices reach each other with and without the internet, where
your data is kept, and what to check when two devices do not connect.

Mycel has no accounts and runs no servers of its own. Each device is its own
identity, and devices reach each other on the local network, over Bluetooth
or peer-to-peer Wi-Fi, over the internet, or through other devices running
Mycel.

> **Mycel is experimental and its cryptography has not had an external
> review.** Do not use it for anything that needs to stay secret yet.

What works on which platform, and how each was tested, is in
[PLATFORMS.md](PLATFORMS.md).

## Contents

- [Before you start](#before-you-start)
- [Install](#install)
- [Name your device](#name-your-device)
- [Add a contact](#add-a-contact)
- [Send messages](#send-messages)
- [Send files](#send-files)
- [Make calls](#make-calls)
- [How devices reach each other](#how-devices-reach-each-other)
- [Reach people through other devices](#reach-people-through-other-devices)
- [Deliver messages to someone who is offline](#deliver-messages-to-someone-who-is-offline)
- [Where data and logs live](#where-data-and-logs-live)
- [Network settings](#network-settings)
- [Troubleshooting](#troubleshooting)
- [For developers](#for-developers)

## Before you start

**Every device must run the same build.** The wire format still changes
between builds, and an older build can miss a newer one's messages or not
see it on the network at all.

The current build refuses profiles, contact codes and stored conversations
made by earlier builds. If you ran an earlier build,
[reset to a new profile](#reset-to-a-new-profile) and exchange contact codes
again.

Each device is its own identity. There is no sign-in and no account to
recover: the identity key on the device is the account.

## Install

Test builds are published as pre-releases on the
[releases page](https://github.com/atullal/mycel/releases); use the newest
one. There is no download for iPhone and iPad: that app has to be built and
signed with your own Apple developer account.

| Platform | Requires | File |
|---|---|---|
| macOS | macOS 11 or later, Apple silicon or Intel | `Mycel_<version>_universal.dmg` |
| Windows | Windows 10 or later | `Mycel_<version>_x64-setup.exe` or the `.msi` |
| Linux | glibc 2.35 or newer | `.deb`, `.rpm` or `.AppImage` |
| Android | Android 9 or later | `Mycel_<version>_android.apk` |
| iPhone and iPad | iOS 16.4 or later | none: build it yourself |

The Linux and Windows files come with a `SHA256SUMS` file and a build
provenance attestation. [PLATFORMS.md](PLATFORMS.md) says how to verify the
attestation, and how to build any of the apps from source.

The sections below give the first launch and the permissions for each
platform. Without the network permissions, devices cannot see or reach each
other.

### macOS

Use a `_notarized.dmg` download from the website. Open the disk image, drag
Mycel to Applications, then open Mycel. These packages are signed with a
Developer ID and notarized by Apple. The website offers the Mac download
only after these checks pass.

Older prereleases contain unsigned DMGs. Use a signed replacement when one
is available. If macOS reports a signed download as damaged, download a fresh
copy and [report the problem](#report-a-problem). Do not remove its quarantine
flag to bypass verification.

macOS then asks for the following. The settings named here are all in
*System Settings*.

- "Allow Mycel to find devices on local networks?" Choose *Allow*. If you
  missed it, turn Mycel on in *Privacy & Security > Local Network*, then quit
  and reopen Mycel.
- "Do you want the application Mycel to accept incoming network
  connections?" This appears only with the macOS firewall on. Choose
  *Allow*. If you missed it, open *Network > Firewall > Options…* and set
  Mycel to *Allow incoming connections*.
- "Mycel would like to use Bluetooth". Choose *Allow*. The setting is in
  *Privacy & Security > Bluetooth*.
- The microphone and the camera, on your first call. The settings are in
  *Privacy & Security > Microphone* and *Camera*.
- A folder, the first time you attach a file from Desktop, Documents or
  Downloads. Choose *Allow*.

### Windows

Run the installer. It is unsigned, so SmartScreen warns: choose
*More info > Run anyway*.

Windows Firewall asks the first time Mycel listens for connections. Allow
private networks, which discovery on the local network needs. Video calls
need the camera allowed for desktop apps, in
*Settings > Privacy & security > Camera*.

### Linux

Install the `.deb` or `.rpm`, or make the AppImage executable and run it.

Sending video in a call needs one of GStreamer's H.264 encoders, x264 or
openh264. The `.deb` recommends `gstreamer1.0-plugins-bad` and
`gstreamer1.0-plugins-ugly`, and the `.rpm` recommends
`gstreamer1-plugin-openh264`.

Bluetooth and Wi-Fi Direct need some set-up first: see
[Bluetooth and Wi-Fi Direct on Linux](#bluetooth-and-wi-fi-direct-on-linux).

### Android

Copy the APK to the phone and open it. Android asks you to allow "Install
unknown apps" for the app you open it from. With a computer attached,
`adb install -r <apk>` does the same.

Android asks to allow notifications (Android 13 and later), and for the
microphone and the camera on your first call. Mycel keeps running in the
background, with a quiet "Mycel is connected" notification.

### iPhone and iPad

Building needs a Mac with Xcode signed in to an Apple developer account:

```sh
scripts/package-ios.sh --install
```

[PLATFORMS.md](PLATFORMS.md) has the details. Before the first launch, open
*Settings > General > VPN & Device Management* on the device and trust the
developer.

iOS asks for Local Network access (without it, only internet paths work),
for Bluetooth, and on first use for the microphone, the camera and photos.
It asks to allow notifications while the app is open.

### Notifications

Mycel notifies you of new messages, message requests and calls when you are
not looking at it. A notification says only what happened ("New message",
"Incoming call"), never a name or any text.

The *Notifications* card in the *Profile* panel shows whether notifications
are allowed, with an *Enable notifications* button when Mycel has not asked
yet.

## Name your device

A new profile is named after the device: the computer's name, or the
phone's. Pick a name the other side will recognise:

1. Open *Profile*, the button showing your avatar.
2. Choose *Change name*, type the new name and choose *Save*.

On a computer the window title shows the name too.

## Add a contact

There are two ways to add someone: find their device nearby, or use their
contact code. Adding on one side is enough for that side to start a
conversation. The other side then receives it as a
[message request](#answer-a-message-request), unless it has added you too.

To remove a contact, open *Contacts* and choose *Remove* beside the name.

### Add someone nearby

Open *Nearby*, the radar button. Within a few seconds, devices running Mycel
on the same network, or within peer-to-peer Wi-Fi or Bluetooth range, appear
by name. Choose *Add* beside one.

People who are nearby but not yet contacts are also listed in the *New
conversation* dialog, under *Nearby, not in contacts*. Picking one there adds
them to your contacts.

### Add someone with a contact code

A **contact code** is a line of text starting with `mycel:` that names a
device. Yours is in *Profile*, under *Your contact code*. It comes in two
forms.

| | Short code and QR code | Full code |
|---|---|---|
| Where to get it | *Copy*, or show the QR code | *Copy full code* |
| Length | about 150 characters, plus addresses | under 2,000 characters |
| What it holds | the device's key and its signed name | the same, plus the device's encryption key |
| Needed before a conversation can start | the two devices must connect once | nothing |

To add someone, get their code, open *Contacts*, paste it under *Add by
contact code* and choose *Add*. Mycel has no QR scanner of its own: scan the
QR code with a camera or any QR reader, and paste the text it gives.

The short code leaves out the device's encryption key, which is too long to
scan. Your device fetches that key from theirs the first time the two
connect, and keeps trying in the background until it does. Until then the
contact is listed with the note *Waiting to connect once before you can
start a conversation*.

Use the full code when the two devices cannot connect first, for example
when you send your code to someone who will add you while you are offline.

Both forms end with the device's current network addresses, the part after
`@`. So a contact code works on a network that blocks discovery, as long as
the two devices can reach each other's address. If the address changes (a
new network, a new DHCP lease), discovery or a fresh code fixes it.

### Answer a message request

A conversation started by someone who is not your contact arrives as a
request, listed under *Requests*. Until you accept it, nothing is sent back:
no profile, no read receipts and no replies. No files are stored, and
attachments and links in the request stay closed.

You have three choices:

- *Accept* adds the sender to your contacts and lets you reply.
- *Decline* leaves the conversation quietly. The sender is not told whether
  you read anything.
- *Block* declines, and also refuses that sender's future invitations at the
  network layer.

## Send messages

1. In *Messages*, choose *New conversation*.
2. Tick one person and choose *Start chat*. Ticking several people creates a
   group, which you can give a *Group name*.
3. Type a message and press Enter, or tap the send button on a phone.
   Shift+Enter starts a new line.

Each of your messages carries a delivery mark:

| Mark | Label | Meaning |
|---|---|---|
| Clock | *Saved on this device* | No other device has the message yet. |
| One tick | *Sent* | Another device, a member's or a keeper's, holds a copy. |
| Two ticks | *Delivered to everyone* | Every other member has it. |
| Two ticks, coloured | *Read by everyone* | Every other member has read as far as this message. |

Replies, reactions, edits, forwarding, typing indicators and group
conversations all work the same way on every platform. How you reach them
depends on the device:

- On a computer, hover over a message for its actions or right-click it.
  Pressing ↑ in an empty composer edits your last message.
- On a phone, long-press a message for its actions and swipe it to reply.

The microphone button, shown while the composer is empty, records a voice
note. You can play it back before choosing *Use recording* to attach it. A
voice note can be up to 5 minutes long.

*Search messages*, the magnifier in a conversation's header, searches that
conversation. The search field above the conversation list finds
conversations by the names of the people or the group.

### Manage a group

Open the conversation's details with the people button in its header. An
admin can rename the group, add people and remove them. Anyone can choose
*Leave group*: the history stays on the device, and no new messages arrive.

### Delete a message

Open a message's actions and choose *Delete*:

- *Delete for me* removes the message from this device's history only. It
  works on any message, and an *Undo* button appears for a few seconds.
- *Delete for everyone* is offered on your own messages. It removes the
  message from the conversation as other devices sync. Copies that people
  saved elsewhere remain.

## Send files

Attach a file with the paperclip button on a computer or the plus button on
a phone, by dragging it onto the conversation, or by pasting it. A phone
also has a camera button. Folders and macOS packages (`.pages`, `.app` and
the like) are sent as a `.zip`.

Files can be any size:

- A file of up to 16 MiB is sent to every member who can be reached, as soon
  as you send the message.
- A larger file is downloaded when the recipient chooses to download it,
  with a progress bar, from every device in the conversation that has it. An
  interrupted download resumes where it stopped.
- A transfer is refused if it would leave less than 1 GiB of free disk
  space.

A downloaded photo shows in the conversation, and audio and video play in
place. Other files have an *Open* button: it opens the file in its default
app on a computer, in the share sheet on an iPhone or iPad, and in an
"Open with" chooser on Android.

### Choose private or public for each file

Each file you attach shows a *Private* label before you send it. Click the
label to send that file as *Public* instead; click again to switch back. The
choice is made per file.

A **private** file is the default. It is encrypted with keys made fresh
each time, so nobody outside the conversation can tell what it is. Attach
the same file twice and the devices that store it see two unrelated files.

A **public** file is encrypted with keys worked out from the file's own
content, so the same file is the same encrypted data wherever it is sent.
That has two effects:

- It is stored once on each device however many people send it, and is sent
  only to devices that do not have it yet. Other devices keep it for as long
  as it is being asked for, so a file many people share is likely to stay
  available. Nothing guarantees that.
- Anyone who already has the same file can tell that you sent it. They can
  check whether a device holds it and find devices that announced it, and
  someone who knows most of a file can test guesses at the rest.

Send as public only what you would not mind having confirmed as yours.
Leave anything personal private. Section 7c of [TRUST.md](TRUST.md) has the
detail.

### Files for people who are away

When a member cannot be given a file, the sender also hands it to a few
devices willing to hold it: its contacts first, then devices nearby on a
fast link. They hold encrypted data they cannot read, and the member
fetches the file from them later.

Your device does the same for others. By default it sets aside up to 1 GiB
of disk space for other people's files, and lets go of the least requested
when it needs room. Files in your own conversations do not count against
that space. [Network settings](#network-settings) says how to change the
amount or turn it off.

## Make calls

### Start or answer a call

In a conversation's header, the phone button starts a voice call and the
camera button a video call. The other side sees three buttons: *Decline*,
*Accept with video* and *Accept*, which answers with voice only. Either side
can turn its camera on or off during the call. You can be in one call at a
time.

While a call is on, the call bar shows its duration, the path in use, the
voice bitrate, a level meter for each side, and buttons for the camera,
*Mute* and *Hang up*.

A call keeps going when its path changes, with a few seconds of silence if
the old path stopped working.

### Call quality on each path

The path sets the best quality a call can have. Mycel lowers the quality
further when a path loses packets or slows down.

| Path | Voice, up to | Video, up to |
|---|---|---|
| Same network, or a cable | 32 kbps | 720p |
| Peer-to-peer Wi-Fi | 32 kbps | 480p |
| Internet relay | 24 kbps | 360p |
| Mesh | 24 kbps | none |
| Bluetooth | 12 kbps | none |

Video starts small and sharpens within seconds. Over Bluetooth or the mesh,
video pauses on both sides ("Video paused: slow connection") while the voice
carries on, and comes back by itself on a faster path.

### Group calls

In a group, the phone button rings everyone. Up to 8 people can be in a
call. Each device connects to every other one directly, so whoever started
the call can leave without ending it. Someone who declined or missed the
call can choose *Join call* for as long as it lasts.

### When a call does not connect

- If both sides call at the same moment, the two calls become one.
- A device that cannot be reached gives "can't be reached right now" after a
  few seconds.
- An unanswered call ends with *No answer* on the caller's side after 45
  seconds, and shows *Missed call* on the other side.

### Echo

macOS, iPhone and iPad use Apple's voice processing, and Android uses its
echo canceller, so speakers are fine on those. Windows and Linux have no
echo cancellation: use headphones, or the other side hears itself.

The call bar shows *Use headphones to avoid echo* whenever the device in use
has no echo cancellation. On an Apple device, that means voice processing
could not start.

## How devices reach each other

A **path** is one way for two devices to exchange data: the network they
share, a direct radio link, the internet, or other Mycel devices in between.
Mycel uses every path it has, prefers the fastest, and moves to another when
one stops working. You do not choose a path, but you can see which are in
use.

### See which paths are in use

Open *Network*. From top to bottom the panel shows:

- a map of the people you know, and counts of those *Connected* and
  *Nearby*;
- *Connections*, where you choose between *All paths* and *Local only*;
- *Paths*, one row per path, saying whether it works and how many devices it
  reaches, or why it does not work (for example "Bluetooth is off");
- *Relaying*, what this device does for others over the internet and which
  devices do the same for it;
- *Talking to*, each person and the path that reaches them now;
- *Listening on*, this device's own addresses.

The paths are named as follows.

| Path | What it is |
|---|---|
| *Same network* | Wi-Fi, Ethernet or a cable between the devices |
| *Peer-to-peer Wi-Fi* | Device to device, as AirDrop does it: Wi-Fi on, but no network |
| *Bluetooth* | Slow, but works with Wi-Fi off |
| *Internet relay* | Through an encrypted relay, for devices on different networks |
| *Cable*, *Wi-Fi Direct*, *UWB*, *Thread / 802.15.4*, *Other link* | Another network interface on the device |
| *Mesh* | Through other nearby Mycel devices, hop by hop |

### On the same network

Devices on one network announce themselves to each other and show up in
*Nearby* within seconds. This needs no internet, only a network that lets
its devices talk to each other; guest and office networks often do not.

### Over the internet

In *All paths* mode, the default, a device also uses the internet.

To be found, each device publishes a signed record saying where it can be
reached. The record goes into the BitTorrent DHT, a public directory that
nobody owns, and onto a DNS server run by n0, the developers of the Iroh
networking library that Mycel is built on. A device that has your contact
code looks the record up by your device's key.

To connect, two devices first try to reach each other directly through
their routers. When the routers do not allow that, the connection goes
through a relay. By default the relay is one of n0's public relay servers.
Devices also relay for each other: one that the internet can reach directly
relays for devices that cannot be reached, when they ask it to, and devices
turn to such a relay when no relay server is connected.

A relay passes on encrypted traffic and cannot read it. What it can still
observe is set out in sections 8b and 8c of [TRUST.md](TRUST.md). n0's relay
servers, n0's DNS server, the DHT and relaying for others can each be
switched off: see [Network settings](#network-settings).

The *Relaying* card in the Network panel says which of these applies to your
device:

- It relays for others: "This device can be reached from the internet, so it
  relays for devices that can't", or the number of devices it is relaying
  for. While it relays, its internet address is public to anyone who has its
  contact code.
- Others relay for it: "The internet can't reach this device directly",
  followed by the devices that pass connections on to it.
- It is on mobile data: "not carrying anyone else's traffic". Such a device
  is neither a relay nor a gateway.

Relaying among devices, and running without n0's servers, have been tested
between processes on one computer, not across real routers.

### Use Mycel without the internet

None of the local paths needs the internet, so Mycel keeps working on a
network whose uplink is down. To make sure it never contacts the internet,
choose *Local only* under *Connections* in the Network panel, then restart
Mycel. A computer offers *Restart now*; a phone asks you to close Mycel and
open it again.

To check that it works with no internet, keep the devices on one local
network and cut the uplink. Unplug the router's internet cable, use a phone
hotspot with mobile data off, or connect two computers with a cable: they
get link-local addresses, and discovery works across the cable. A website
should then fail to load on both devices.

### Connect with no shared network

Two devices do not need to share a network. Macs, iPhones and iPads can link
over peer-to-peer Wi-Fi and Bluetooth, and Linux computers over Bluetooth.
Android and Windows have neither.

Bluetooth has run between a real iPhone and Macs, for far less time than on
emulated links. **Peer-to-peer Wi-Fi, and Bluetooth and Wi-Fi Direct on
Linux, have been tested only on emulated links, not between real devices.**
Trying them on real devices is the most useful testing there is.

To try it, watch the *Talking to* list in the Network panel while you change
the radios:

1. Leave the Wi-Fi network but keep Wi-Fi on: disconnect from or forget the
   network, and unplug Ethernet. Within a few seconds Mycel should switch to
   *Peer-to-peer Wi-Fi*, the Apple radio link that AirDrop uses, at Wi-Fi
   speed. Its range is roughly a room or two.
2. Turn Wi-Fi off and keep Bluetooth on. Mycel falls back to *Bluetooth*. It
   carries tens of kilobytes a second: fine for text, slow for photos and
   impractical for large files. It reaches across a room.
3. Turn Wi-Fi back on or rejoin the network. Mycel moves back to the faster
   path by itself.

A transfer or call in progress moves to the next path when the current one
stops working. Noticing that takes about 5 seconds.

If a path does not come up, its row in the *Paths* list says why: for
example "Bluetooth is off", or a permission to allow.

### Cables and other network interfaces

On macOS, iPhone, iPad, Android and Linux, Mycel uses every network
interface the device has. Each becomes its own path, named in the *Paths*
list by what it is, such as "Cable bridge0" or "Wi-Fi Direct p2p-wlan0-0".
A faster path wins and slower ones stay as backups.

A Thunderbolt or USB-C cable between two Macs is one example. The bridge
interface gets a link-local address and becomes a *Cable* path, with no
network at all.

Interfaces need no special permission. An interface with IPv6 switched off
cannot be used.

Macs have no UWB radio. On Linux, a UWB radio carries data only if its
driver presents it through the kernel's IEEE 802.15.4 stack as a 6LoWPAN
interface (`ip link add link wpan0 name lowpan0 type lowpan`). Most UWB
chips only measure distance.

### Bluetooth and Wi-Fi Direct on Linux

Bluetooth on Linux goes through BlueZ, and links with Macs too.
`bluetoothd` must be running and your user must be allowed to advertise. On
distributions whose BlueZ D-Bus policy uses the `bluetooth` group, add
yourself to it and log in again:

```sh
sudo usermod -aG bluetooth $USER
```

No pairing is needed.

Wi-Fi Direct is off by default, because it takes over the peer-to-peer side
of the Wi-Fi radio. Start Mycel with `MYCEL_WIFI_DIRECT=1` to turn it on. It
needs:

- wpa_supplicant running with its D-Bus interface (`-u`);
- a Wi-Fi driver that supports P2P;
- permission to use wpa_supplicant's D-Bus interface: root, or the `netdev`
  group on Debian and Ubuntu.

Mycel devices then find each other and form a group with no prompt, and the
group's `p2p-*` interface shows up as a path. NetworkManager may also try to
manage that interface.

## Reach people through other devices

Every device running Mycel also passes traffic on for others. It cannot read
what it passes on. How this works is described in
[ARCHITECTURE.md](ARCHITECTURE.md) and [ROUTING.md](ROUTING.md), and what
the devices in between learn in sections 8b and 8c of
[TRUST.md](TRUST.md).

### The mesh

Two devices out of each other's range can reach each other through a third
Mycel device between them, even one that is in none of their conversations.
This is the **mesh**.

A direct path always wins, so with two devices the mesh never shows. With
three devices, where A and C are out of range of each other and B is in
range of both, the Network panel on A shows C as "via Mesh (via B, 2 hops)".

### Gateways

A device with the internet is a **gateway** for nearby devices without it.
A device that has only Bluetooth, near a gateway, can be messaged and called
from anywhere on the internet. Its Network panel says "internet via" and
the gateway's name.

### Carried messages

When nobody can reach a member live, what that member lacks travels as a
signed, still-encrypted bundle. It moves along whatever part of the way is
up, toward devices with the internet, and waits at the member's gateway.

A device that carries bundles holds at most 64 MiB for others and 4 MiB for
any one sender, for up to 7 days. It learns who a bundle is for and how big
it is, never what is in it.

## Deliver messages to someone who is offline

A message waits on the sender's device until a recipient or a keeper has it.
You can see this with two devices: quit Mycel on B and send from A, and the
mark stays a clock. Reopen B, and within seconds of the two finding each
other the messages arrive and A's mark changes to *Delivered to everyone*.

So the sender has to be running when the recipient comes back, unless a
keeper holds the conversation.

### Run a keeper

A **keeper** is an always-on device that stores encrypted copies of a
conversation and passes them to its members. It cannot read them.

A keeper runs from the command line, on any computer with Rust and this
repository:

```sh
cargo build --release -p mycel-cli
./target/release/mycel keeper --data ~/.mycel-keeper --name "Keeper" --net lan
```

`--net lan` keeps the keeper on local paths. Leave it out for a keeper that
people reach over the internet too.

The keeper prints its short contact code. To use it:

1. Add the keeper as a contact, from a device that can reach it.
2. Open the conversation's details and find *Keepers*.
3. Choose *Add a keeper*, pick the keeper and choose *Add keeper*.

Only an admin of the conversation can add a keeper. From then on A can send
while B is offline and then quit: B gets the messages from the keeper later.

### Phones in the background

A suspended iPhone or iPad does not receive messages until Mycel is opened
again. Waking it would need Apple's push service, which needs a server.
Calls continue in the background.

Android keeps Mycel running in the background.

## Where data and logs live

| Platform | Data folder |
|---|---|
| macOS | `~/Library/Application Support/dev.mycel.host/` |
| Windows | `%APPDATA%\dev.mycel.host\` |
| Linux | `~/.local/share/dev.mycel.host/` |
| iPhone, iPad | inside the app's container |
| Android | the app's private data folder |

On a phone, a development build lets you read the folder: through Xcode's
*Devices and Simulators* window on an iPhone or iPad, and with
`adb shell run-as dev.mycel.host ls` on an Android debug build.

The folder holds:

| Name | Contents |
|---|---|
| `identity.key` | The device's identity key |
| `mycel.redb` | Messages, contacts and settings |
| `files/` | Attachments you have downloaded, decrypted |
| `blobs/` | Encrypted file data, yours and what the device holds for others |
| `mycel.log`, `mycel.log.1` | The log of this run and of the one before |

### The identity key

**`identity.key` is your account.** Anyone who has it can act as you, and
there is no recovery if it is lost.

On an iPhone or iPad the key is kept in the Keychain instead of the file. On
iPhone, iPad and Android the data folder is kept out of backups. A new phone
is therefore a new identity, and conversations come back from the other
members once the new device has been added to them.

### Logs

Started from Finder, the Start menu or a phone's home screen, Mycel writes
its log to `mycel.log` in the data folder. The previous run's log is kept as
`mycel.log.1`.

Started from a terminal, Mycel logs to the terminal instead. On a Mac:

```sh
/Applications/Mycel.app/Contents/MacOS/mycel-host
```

Logs can hold device names, keys and network addresses. Look them over
before you share them.

### Reset to a new profile

Quit Mycel and delete the whole data folder. On macOS:

```sh
rm -rf ~/Library/Application\ Support/dev.mycel.host
```

On Windows and Linux, delete the folder in the table above. On a phone,
delete the app and install it again.

The next launch creates a new identity, and your contacts will see a new,
different person. Delete the folder as a whole: if only `identity.key` is
missing from an existing profile, Mycel refuses to start instead of creating
a replacement.

## Network settings

A few settings change which outside services a device uses and what it does
for others. They are environment variables, read when Mycel starts, so they
apply to the desktop apps started from a terminal and to the `mycel` command.
The phone apps have no way to set them.

| Variable | Effect |
|---|---|
| `MYCEL_RELAYS=none` | Use no relay server. The default is `n0`; a comma-separated list of URLs names your own servers. |
| `MYCEL_N0_DNS=0` | Do not publish or look up records on n0's DNS server. |
| `MYCEL_DHT=0` | Do not use the BitTorrent DHT. |
| `MYCEL_INTERNET_RELAY=0` | Do not relay over the internet for other devices. |
| `MYCEL_MESH_RELAY=0` | Use the mesh, but forward no live traffic for other devices. Messages waiting for someone who is offline are still carried. |
| `MYCEL_FILE_CACHE_MB=<n>` | Disk space, in MiB, for holding other people's files. The default is 1024; `0` holds none. |

To run with no server at all, only other devices and the DHT, on a Mac:

```sh
MYCEL_RELAYS=none MYCEL_N0_DNS=0 /Applications/Mycel.app/Contents/MacOS/mycel-host
```

Without a relay server, a device is reached directly if the internet can
dial in to it, and otherwise through devices that relay for it. With both
`MYCEL_N0_DNS=0` and `MYCEL_DHT=0`, devices find each other only nearby and
through contact codes.

[CONFIGURATION.md](CONFIGURATION.md) lists every setting.

## Troubleshooting

### A device does not appear in Nearby

- Both devices must be on the same network and subnet: compare the first
  three numbers of their IP addresses. A device on one router's Ethernet and
  one on another router's Wi-Fi do not see each other.
- Guest, hotel, office and campus networks often isolate devices from each
  other and block discovery. Use a home network, a phone hotspot or a direct
  cable.
- Check the Local Network permission (macOS, iPhone, iPad) and the firewall
  (macOS, Windows, third-party firewalls). "Block all incoming connections"
  must be off.
- A VPN can hide the local network. Disconnect it for the test.
- Wait 10 to 20 seconds: announcements are periodic. Reopening Mycel on both
  sides sends fresh ones.
- Check that both run the same build. Older builds cannot see an iPhone
  running a newer one.

If the device still does not appear, the network is probably blocking
discovery (multicast on UDP port 5353). Exchange contact codes instead: they
carry the addresses, so the devices connect without discovery. If that fails
too, the network blocks traffic between its devices, and you need a
different network.

### A contact stays on "Waiting to connect once"

The contact was added from a short code or QR code, and your device has not
reached theirs yet to fetch its encryption key. Starting a conversation with
them fails until it has.

Mycel keeps trying, and it succeeds once the other device is online or
nearby. If the two devices cannot be online together, ask for the full code
(*Copy full code*) and add that.

### A contact code is not accepted

"not a Mycel contact code (or one made by an older version of Mycel)" means
the text is incomplete or was made by an earlier build. Copy the whole code
again, from a device running the same build as yours.

### Messages stay on the clock or on one tick

The other side is offline or cannot be reached. In the Network panel, the
*Talking to* list should show a path for that person, not *Not reachable*.
Messages are delivered automatically when the device comes back.

### Peer-to-peer Wi-Fi or Bluetooth does not connect

Look at the path's row in the *Paths* list of the Network panel first: it
names a radio that is off or a permission that is missing.

If the row looks right and two devices still do not link, collect the link
logs described under [Turn on link logs](#turn-on-link-logs) and
[report the problem](#report-a-problem).

### macOS says Mycel is damaged and can't be opened

Older prereleases were unsigned. Use the signed, notarized package offered
on the website when available. For a `_notarized.dmg` download, try a fresh
copy and [report the problem](#report-a-problem) if the warning persists.

### Mycel says another copy is using the data folder

Only one copy of Mycel can use a data folder at a time. Quit the other copy.
To run two on purpose, see
[Run several copies on one computer](#run-several-copies-on-one-computer).

### Report a problem

Include the platform, how Mycel was installed, the steps, and `mycel.log`
from each device involved. [Logs](#logs) says where the file is and what it
can reveal.

Security problems go through [SECURITY.md](../SECURITY.md), not public
issues.

## For developers

This section is for people working on Mycel or testing it from a terminal.
[CONFIGURATION.md](CONFIGURATION.md) lists every environment variable.

### Run several copies on one computer

Each copy needs its own data folder. A second copy started on a folder that
is in use shows an error and quits.

```sh
APP=/Applications/Mycel.app/Contents/MacOS/mycel-host
MYCEL_DATA_DIR=/tmp/mycel-a MYCEL_NAME="Laptop A" MYCEL_NET=lan "$APP" &
MYCEL_DATA_DIR=/tmp/mycel-b MYCEL_NAME="Laptop B" MYCEL_NET=lan "$APP" &
```

`MYCEL_DATA_DIR` sets the data folder. `MYCEL_NAME` sets the display name,
replacing the saved one on every launch. `MYCEL_NET` is `internet` (every
path, the default), `lan` (local paths only) or `local` (this computer
only), and overrides the choice made in the Network panel.

### Turn on link logs

`MYCEL_BLE_LOG=1` logs what the Bluetooth link does, and `2` logs every
state change. `MYCEL_AWDL_DEBUG=1` logs the peer-to-peer Wi-Fi link. On a
Mac:

```sh
MYCEL_AWDL_DEBUG=1 MYCEL_BLE_LOG=2 /Applications/Mycel.app/Contents/MacOS/mycel-host
```

A phone has no environment variables. There, a file named `link-diagnostics`
in the data folder, holding `1` or `2`, turns on the Bluetooth log (iPhone
and iPad only: Android has no Bluetooth link).

### Run a device from the terminal

The `mycel` command, built with `cargo build -p mycel-cli`, can be a full
device without the app:

```sh
./target/debug/mycel serve --data ~/.mycel-cli --name "Terminal" --net lan
```

Open <http://127.0.0.1:7777> for the same UI in a browser (build it first
with `npm install && npm run build`), or script the device with
`mycel call <command> '<json>'` ([RUNTIME_API.md](RUNTIME_API.md)).
`mycel id` prints a device's short and full contact codes.
