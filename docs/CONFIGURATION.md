# Configuration

This document lists everything that can be set when running Mycel: the
options of the `mycel` command, and every `MYCEL_*` environment variable the
code reads. It is for people who run the desktop app or the command from a
terminal, and for developers testing Mycel. The other documents link here
instead of listing settings themselves.

Mycel has no configuration file. A setting is an environment variable, a
command-line option, or one of the two choices the app saves.

## Contents

- [How settings are given](#how-settings-are-given)
- [Common setups](#common-setups)
- [The `mycel` command](#the-mycel-command)
- [Network and services](#network-and-services)
- [Links](#links)
- [Storage and identity](#storage-and-identity)
- [Calls and video](#calls-and-video)
- [Logging and debugging](#logging-and-debugging)
- [Tests, benchmarks and the simulator](#tests-benchmarks-and-the-simulator)
- [Build scripts](#build-scripts)

## How settings are given

The desktop app and the `mycel` command read environment variables when
they start. The app has no screen for them, so start it from a terminal.
Its executable is called `mycel-host` on every desktop platform. On a Mac:

```sh
MYCEL_RELAYS=none MYCEL_N0_DNS=0 /Applications/Mycel.app/Contents/MacOS/mycel-host
```

The `mycel` command reads the same variables, except three that it takes as
options and ignores as variables:

| The app reads | The command takes |
|---|---|
| `MYCEL_DATA_DIR` | `--data` |
| `MYCEL_NAME` | `--name` |
| `MYCEL_NET` | `--net` |

### Phones

The phone apps cannot be given environment variables.

On Android, a system property stands in for six of them. When the app
starts it reads `debug.mycel.<name>` for the names `audio`, `video_debug`,
`net`, `links`, `mesh` and `ble_log`, and uses the value as that of
`MYCEL_AUDIO`, `MYCEL_VIDEO_DEBUG` and so on:

```sh
adb shell setprop debug.mycel.net lan
```

Android has no Bluetooth link, so `ble_log` changes nothing there.

On iPhone and iPad the one setting of this kind is the `link-diagnostics`
file described under [Link logs](#link-logs).

### Values

Values are matched exactly as the tables give them. A switch that is turned
off with `0` is not turned off by `false`, `no` or `off`. Most variables
ignore a value they do not recognise, without a warning. `MYCEL_NET` and
`MYCEL_RELAYS` stop Mycel from starting instead, and say why.

### What the app saves

Two settings can be changed in the app, and are saved in the data folder.

| Setting | Changed in | Overridden by |
|---|---|---|
| Network mode | The *Network* panel, under *Connections* | `MYCEL_NET`, `--net` |
| Display name | The *Profile* panel | `MYCEL_NAME`, `--name` |

The network mode is fixed while Mycel runs, so a new choice takes effect at
the next start. `MYCEL_NET` and `--net` decide the mode for one run and
leave the saved choice as it was. While either is given, a mode chosen in
the *Network* panel is saved but not used.

`MYCEL_NAME` and `--name` replace the saved name every time Mycel starts
with them.

Nothing else is saved: every other variable has to be set each time Mycel
starts.

## Common setups

### Use no outside server

In its default mode a device uses three outside services: n0's relay
servers, n0's DNS server, and the BitTorrent Mainline DHT. n0 is the
company that develops Iroh, the transport Mycel is built on; the DHT has no
operator. To use the DHT and other devices only:

```sh
MYCEL_RELAYS=none MYCEL_N0_DNS=0 /Applications/Mycel.app/Contents/MacOS/mycel-host
```

```sh
MYCEL_RELAYS=none MYCEL_N0_DNS=0 mycel serve
```

A device is then found by its record in the DHT, and reached directly or
through devices that relay for it. Leave the DHT on:
[without it](#outside-services) a device with no relay server takes no part
in that relaying.

This setup is tested between processes on one computer, not through real
routers. [ARCHITECTURE.md](ARCHITECTURE.md) lists what it cannot do yet.

### Stay off the internet

*Local only* mode uses the same network, the links and the mesh, and no
relay server, DNS server or DHT.

In the app, open the *Network* panel, choose *Local only* under
*Connections*, and restart Mycel. The choice is saved.

For one run, or with the command, select the mode `lan`:

```sh
MYCEL_NET=lan /Applications/Mycel.app/Contents/MacOS/mycel-host
```

```sh
mycel serve --net lan
```

### Do not relay for others

```sh
MYCEL_MESH_RELAY=0 MYCEL_FILE_CACHE_MB=0 mycel serve
```

`MYCEL_MESH_RELAY=0` stops the device carrying live traffic for others: as
a hop in the mesh, as a gateway and as an internet relay. The device still
uses all three itself. `MYCEL_FILE_CACHE_MB=0` stops it holding files for
others.

The device still carries store-and-forward bundles for other devices.
Only `MYCEL_MESH=0` stops that, and it takes the device off the mesh
altogether. [The mesh and relaying](#the-mesh-and-relaying) has the detail,
and the switch that stops relaying over the internet only.

### Run several copies on one computer

Each copy needs its own data folder. A second copy started on a folder
that is in use stops with an error.

```sh
APP=/Applications/Mycel.app/Contents/MacOS/mycel-host
MYCEL_DATA_DIR=/tmp/mycel-a MYCEL_NAME="Laptop A" "$APP" &
MYCEL_DATA_DIR=/tmp/mycel-b MYCEL_NAME="Laptop B" "$APP" &
```

With the command, each copy also needs its own address for the interface:

```sh
mycel serve --data /tmp/a --name Alice --http 127.0.0.1:7701 &
mycel serve --data /tmp/b --name Bob --http 127.0.0.1:7702 &
```

Add `MYCEL_NET=lan` or `--net lan` to keep the copies off the internet.

## The `mycel` command

`mycel` runs a device from a terminal, with no app. Build it with
`cargo build -p mycel-cli`; the binary is `target/debug/mycel`, or
`target/release/mycel` with `--release`. The examples here write `mycel`
for that path. `mycel --help` and `mycel <subcommand> --help` print the
options.

```text
mycel serve  [--data <dir>] [--name <name>] [--net <mode>] [--port <port>]
             [--http <address>] [--ui <dir>]
mycel keeper [--data <dir>] [--name <name>] [--net <mode>] [--port <port>]
mycel id     [--data <dir>]
mycel call   <command> [<json>] [--http <address>] [--data <dir>]
```

### Device options

`serve` and `keeper` each run a device, and share these options.

| Option | Default | Meaning |
|---|---|---|
| `--data <dir>` | `~/.mycel` | The data directory: identity, messages and files |
| `--name <name>` | the saved name | The display name. It is saved |
| `--net <mode>` | the saved mode, else `internet` | The [network mode](#network-mode): `internet`, `lan` or `local` |
| `--port <port>` | `0`, a random port | The UDP port for connections from other devices |

The command's default data directory is not the app's, so the two do not
share a profile unless `--data` points at the app's folder. Only one
process can use a data directory at a time.
[Storage and identity](#storage-and-identity) says what the directory must
be.

A new profile is named after the computer, or `Keeper` for a keeper.

`--port` applies in the `lan` and `local` modes. In `internet` mode it has
no effect, and the system picks the port.

### `mycel serve`

Runs a full device and serves the Mycel interface and the HTTP API on the
local computer.

| Option | Default | Meaning |
|---|---|---|
| `--http <address>` | `127.0.0.1:7777` | Where the interface and the API are served |
| `--ui <dir>` | found automatically | The built interface, `apps/host/dist` |

`--http` must be a loopback address. `serve` refuses any other, because
anyone who can reach the API can use the account.

Without `--ui`, `serve` looks for `apps/host/dist` in the repository the
binary was built in, then under the working directory. `npm run build`
makes that directory. If there is none, `serve` offers the API alone.

`serve` writes its address and a token for this run to `http-token` in the
data directory, readable by the owner only. Every API request needs the
token. [RUNTIME_API.md](RUNTIME_API.md) describes the API.

### `mycel keeper`

Runs a keeper: an always-on device that accepts every conversation it is
added to, stores the conversation's encrypted data and passes it to the
members. It cannot read the data, and it takes no calls.

The keeper prints its contact code and runs until interrupted.
[USER_GUIDE.md](USER_GUIDE.md) says how to add it to a conversation.

```sh
mycel keeper --data ~/.mycel-keeper --net lan
```

### `mycel id`

Prints the device's name, its id, and its short and full contact codes.

`id` opens the profile itself, in `local` mode. It fails while another
process is using the data directory; ask a running `serve` with
`mycel call get_profile` instead. On a directory with no profile, it
creates one.

### `mycel call`

Sends one runtime command to a running `mycel serve` and prints the answer
as JSON. The exit status is 1 if the command failed.

| Argument or option | Default | Meaning |
|---|---|---|
| `<command>` | | The command's name, as in [RUNTIME_API.md](RUNTIME_API.md) |
| `<json>` | `{}` | The command's arguments, as a JSON object |
| `--http <address>` | `127.0.0.1:7777` | The address the `serve` listens on |
| `--data <dir>` | `~/.mycel` | The data directory of that `serve`, where the token is read |

```sh
mycel call list_conversations
mycel call send_message '{"id": "<conversation id>", "body": "hello"}'
```

## Network and services

### Network mode

The mode decides which kinds of path a device uses at all.

| Mode | Name in the app | What the device uses |
|---|---|---|
| `internet` | All paths | Every path: the local ones, direct connections over the internet, relay servers, and the DNS server and DHT |
| `lan` | Local only | The same network, the links and the mesh. No relay server, DNS server or DHT |
| `local` | This device only | The loopback address only: no discovery, no links, no mesh. For tests |

| Variable | Values | Default | Effect |
|---|---|---|---|
| `MYCEL_NET` | `internet`, `lan`, `local` | the saved mode, else `internet` | The app's mode for this run |

`local` cannot be chosen in the app. Two devices in `local` mode on one
computer reach each other through the addresses in their contact codes.

If the saved mode cannot be read and no mode is given, Mycel starts in
`lan` mode, repairs the file and shows a notice.

### Outside services

These apply in `internet` mode only. In the other modes none of the three
services is used.

| Variable | Values | Default | Effect |
|---|---|---|---|
| `MYCEL_RELAYS` | `n0`, `none`, or relay URLs | `n0` | Which relay servers carry traffic when two devices cannot connect directly |
| `MYCEL_N0_DNS` | `0` | on | `0`: do not publish this device's record on n0's DNS server, or look others up there |
| `MYCEL_DHT` | `0` | on | `0`: do not use the Mainline DHT, for records or for finding who holds a file |

With `MYCEL_N0_DNS=0` and `MYCEL_DHT=0` together, a device publishes no
record and looks none up. Devices then find each other only nearby and
through contact codes.

A device learns from the DHT whether the internet can dial in to it. With
`MYCEL_DHT=0` it therefore never becomes an
[internet relay](#the-mesh-and-relaying) unless `MYCEL_REACHABLE=1` says it
can be reached. With no relay server either, it cannot tell that it is
online, and neither relays, nor acts as a gateway, nor asks other devices
to relay for it.

#### `MYCEL_RELAYS`

| Value | Meaning |
|---|---|
| unset, `n0` | n0's public relay servers |
| `none` (also `off`, `0`) | No relay server. Devices relay for each other |
| one or more URLs, separated by commas | Your own relay servers, each an `iroh-relay` |

```sh
MYCEL_RELAYS=https://relay1.example.org,https://relay2.example.org mycel serve
```

A URL that cannot be parsed stops Mycel from starting, and the error names
it.

A relay server sees only encrypted traffic. With `none`, a device that the
internet cannot dial in to is reached through devices that relay for it;
[ARCHITECTURE.md](ARCHITECTURE.md) describes how.

### The mesh and relaying

The **mesh** carries traffic through other Mycel devices, hop by hop. A
**gateway** passes traffic between nearby devices and the internet. An
**internet relay** is a device the internet can dial in to, which carries
traffic for devices that cannot be dialled and have asked it to. All three
are on by default. The mesh runs in the `internet` and `lan` modes;
gateways and internet relays need `internet` mode.

| Variable | Values | Default | Effect |
|---|---|---|---|
| `MYCEL_MESH` | `0` | on | `0`: turn the mesh off |
| `MYCEL_MESH_RELAY` | `0` | on | `0`: use the mesh, but carry no live traffic for other devices |
| `MYCEL_INTERNET_RELAY` | `0` | on | `0`: never be an internet relay |
| `MYCEL_REACHABLE` | `1`, `0` | detected | Whether the internet can dial in to this device |
| `MYCEL_METERED` | `1`, `0` | detected | Whether the uplink is metered |

`MYCEL_MESH=0` removes everything built on the mesh: paths through nearby
devices, gateways, relaying among devices in both directions, and
store-and-forward bundles.

`MYCEL_MESH_RELAY=0` stops the device forwarding for nearby devices, being
a gateway and being an internet relay. The device still reaches others
through the mesh, and still accepts and carries store-and-forward bundles
for other devices.

`MYCEL_INTERNET_RELAY=0` stops only the internet relay. The device still
forwards for nearby devices and is still a gateway.

A device finds out by itself whether the internet can dial in to it. While
it can, the device is an internet relay. While it cannot, and no relay
server is connected, the device asks others to relay for it.
`MYCEL_REACHABLE=1` or `0` replaces the check with the answer given.

A device whose uplink is metered is neither a gateway nor an internet
relay; it still relays between devices near it. Mycel treats the uplink as
metered when the default route leaves through a mobile-data interface. It
does not recognise a phone's hotspot or a tethered phone, which look like
any Wi-Fi or Ethernet network; `MYCEL_METERED=1` says so instead.

The budgets that bound relaying are in [ARCHITECTURE.md](ARCHITECTURE.md)
and [TRUST.md](TRUST.md).

### Other network switches

| Variable | Values | Default | Effect |
|---|---|---|---|
| `MYCEL_IP` | `0` | on | `0`: remove the direct IP transport, to test the links |
| `MYCEL_NATIVE_MDNS` | `1` | off | macOS: discover devices on the same network through the system's Bonjour |

`MYCEL_IP=0` removes Iroh's IP transport. The device then makes no direct
IP connection over Wi-Fi, Ethernet or the internet, and traffic has to use
the links. It is a testing aid and not a way to stay off the internet: in
`internet` mode the relay servers, the DNS server and the DHT are still
used. The interface link still leaves ordinary network cards alone.

`MYCEL_NATIVE_MDNS=1` replaces Iroh's own mDNS with Bonjour on a Mac.
iPhone and iPad always use Bonjour. A device using one discovers devices
using the other.

## Links

A **link** is a path Mycel adds beside Iroh's IP transport: a radio or a
network interface. Links run in the `internet` and `lan` modes.

| Name | Link | Platforms | By default |
|---|---|---|---|
| `awdl` | Peer-to-peer Wi-Fi (Apple's AWDL) | macOS, iOS | on |
| `ble` | Bluetooth LE | macOS, iOS, Linux | on |
| `iface` | Network interfaces: any other interface the system has | macOS, iOS, Linux, Android | on |
| `wifidirect` | The interface link, also forming Wi-Fi Direct groups | Linux | off |

Windows has none of these, so the variables in this section do nothing
there.

| Variable | Values | Default | Effect |
|---|---|---|---|
| `MYCEL_LINKS` | `all`, `none`, or link names | `all` | Which links run |
| `MYCEL_WIFI_DIRECT` | `1` | off | Linux: add `wifidirect` to the default links |
| `MYCEL_IFACES` | interface names | every interface | The only interfaces the interface link may use |
| `MYCEL_IFACE_MEDIUM` | `interface=medium` pairs | detected | What medium an interface is |
| `MYCEL_AWDL_ANY_INTERFACE` | any value but `0` or empty | off | macOS, iOS: let peer-to-peer Wi-Fi use any interface. For tests |
| `MYCEL_BLE_SCAN_ALL` | `1` | off | macOS, iOS: scan for every Bluetooth LE device |

`MYCEL_AWDL_ANY_INTERFACE` drops the restriction to peer-to-peer Wi-Fi, so
that two copies on one Mac can link over loopback or the local network.

`MYCEL_BLE_SCAN_ALL=1` logs each device seen that is not Mycel, which shows
that the radio is receiving. The lines appear at
[`MYCEL_BLE_LOG`](#link-logs) level 1 and above. Scanning for everything
costs battery.

### `MYCEL_LINKS`

| Value | Links that run |
|---|---|
| unset, `all` | Every link the platform has, except `wifidirect` |
| `none` | None: IP paths and the mesh only |
| names, separated by commas | Those links |

```sh
MYCEL_LINKS=ble mycel serve              # no link but Bluetooth
MYCEL_LINKS=all,wifidirect mycel serve   # the defaults plus Wi-Fi Direct
```

`uwb`, `thread`, `802154`, `802.15.4`, `p2p` and `interfaces` are other
names for `iface`, and `wifi-direct` is another for `wifidirect`. Names are
not case-sensitive. A name that the platform lacks, or that is not a link,
is ignored, so a list of only such names runs no link.

`wifidirect` includes `iface`. `MYCEL_WIFI_DIRECT=1` adds it only when
`MYCEL_LINKS` is unset or contains `all`. Forming Wi-Fi Direct groups goes
through `wpa_supplicant` and takes over the Wi-Fi radio's peer-to-peer
side. It is tested on emulated links only.

`MYCEL_LINKS` does not switch the mesh; `MYCEL_MESH` does.

### `MYCEL_IFACES` and `MYCEL_IFACE_MEDIUM`

The interface link makes each network interface a path of its own. It
decides about every interface in this order:

1. It skips an interface that is down, is loopback, has no multicast or no
   IPv6 link-local address, or is a VPN, a tunnel, part of a container or
   virtual machine, or AWDL.
2. If `MYCEL_IFACE_MEDIUM` names the interface, it uses it as that medium.
3. It recognises a radio by its hardware type or its name: IEEE 802.15.4
   and 6LoWPAN (a name starting `wpan`, `lowpan` or `thread`), UWB (`uwb`
   anywhere in the name), Wi-Fi Direct (starting `p2p`), Wi-Fi Aware
   (starting `nan`) and a Wi-Fi mesh (`mesh` anywhere in the name).
4. It skips an ordinary network card that has a routable address, because
   the IP transport already uses it. A card with link-local addresses
   only, such as a Thunderbolt cable between two Macs or a network with no
   DHCP, becomes a path.

`MYCEL_IFACES` is a list of interface names, separated by commas. The link
then considers only those. It narrows the choice and never widens it: a
listed interface still has to pass the rules above.

`MYCEL_IFACE_MEDIUM` is a list of `interface=medium` pairs. It tells the
link what an interface is when the rules cannot, and makes it a path even
where rule 4 would skip it. It does not override rule 1.

```sh
MYCEL_IFACES=wpan0,mesh0 MYCEL_IFACE_MEDIUM=wpan0=uwb,mesh0=other mycel serve
```

| Medium | Other names accepted |
|---|---|
| `uwb` | |
| `802154` | `ieee802154`, `thread`, `6lowpan`, `lowpan`, `zigbee` |
| `wifidirect` | `p2p` |
| `ethernet` | `cable`, `wired` |
| `network` | `wifi`, `lan` |
| `other` | |

Case, spaces, `-`, `_` and `.` in a medium's name are ignored, so
`802.15.4` and `Wi-Fi-Direct` work. A pair with an unknown medium is
dropped.

The medium decides how the path is named in the *Network* panel, the
speed that path selection assumes until it has measured the path, and how
much video a call sends over it.

To see what the link makes of this computer's interfaces, with both
variables applied:

```sh
cargo run -p mycel-link-iface --example ifaces
```

The full rules are in `crates/mycel-link-iface/src/classify.rs`.

## Storage and identity

| Variable | Values | Default | Effect |
|---|---|---|---|
| `MYCEL_DATA_DIR` | a directory | the platform's app-data folder | App: where the profile is kept |
| `MYCEL_NAME` | text | the saved name | App: the display name |
| `MYCEL_FILE_CACHE_MB` | a whole number of MiB | `1024` | Disk space for holding other people's files; `0` holds none |

The data directory holds the identity key, the database, attachments and
the log. [USER_GUIDE.md](USER_GUIDE.md) lists the app's default folder on
each platform and what is in it. These hold for `MYCEL_DATA_DIR` and for
`--data`:

- Mycel creates the directory if it is missing. On Unix it restricts the
  directory to its owner.
- It must be a real directory. Mycel refuses a symbolic link.
- One process uses it at a time. A second stops with "this Mycel profile
  is already open in another process".

A name given with `MYCEL_NAME` or `--name` is saved and is the name new
contacts and nearby devices see. Existing conversations are not told of
it. They are when the name is changed in the *Profile* panel or with
`mycel call set_name`.

`MYCEL_FILE_CACHE_MB` bounds only files held for others. Files that belong
to the device's own conversations count against no budget.
[TRUST.md](TRUST.md) describes the cache.

## Calls and video

| Variable | Values | Default | Effect | Platforms |
|---|---|---|---|---|
| `MYCEL_AUDIO` | see below | `auto` | The audio backend for calls | all |
| `MYCEL_VIDEO` | `test` | the camera | Send a moving test picture, 720p at 30 fps | macOS, iOS |
| `MYCEL_VIDEO_BLUETOOTH_KBPS` | a whole number of kbit/s | no video on Bluetooth | Send 160×90 video at 5 fps within that rate when the call's path is Bluetooth | macOS, iOS, Linux |
| `MYCEL_VIDEO_CHUNK` | bytes, 1 or more | 200 to 1200, by bitrate | How much of a video frame is handed to QUIC at a time | all |
| `MYCEL_VIDEO_NO_LOW_LATENCY` | any value | unset | Start the H.264 encoder in its standard mode, not its low-latency mode | macOS, iOS |
| `MYCEL_VIDEO_NO_LIMIT` | any value | unset | Do not cap the encoder at 1.5 times the bitrate in any second | macOS, iOS |

All but `MYCEL_AUDIO` are for testing and measurement.

On Android, Windows and Linux the web view captures and encodes video, so
`MYCEL_VIDEO=test` sends no picture there.

### `MYCEL_AUDIO`

| Value | Backend |
|---|---|
| unset, `auto` | Voice processing with echo cancellation on macOS and iOS; the phone's call audio with echo cancellation on Android; the default devices elsewhere |
| `device` (also `cpal`) | The default input and output devices, with no echo cancellation |
| `test`, `test:<hz>` | A sine tone as the microphone, 440 Hz unless given. Nothing is played |
| `test:bursts`, `test:bursts:<hz>` | Tone bursts as the microphone, 1000 Hz unless given, to measure the echo that comes back |
| `test:echo` | Plays nothing and sends back what it hears |

The `test` backends use no microphone or speaker, for testing on a machine
without them.

## Logging and debugging

Each variable below adds lines to the log on standard error. An app that
was not started from a terminal writes them to `mycel.log` in its data
folder ([USER_GUIDE.md](USER_GUIDE.md)).

| Variable | Turned on by | What it logs |
|---|---|---|
| `MYCEL_BLE_LOG` | `1` or `2` | The Bluetooth link ([below](#link-logs)) |
| `MYCEL_AWDL_DEBUG` | any value but `0` or empty | The peer-to-peer Wi-Fi link: discovery and flows |
| `MYCEL_IFACE_LOG` | `1` | The interface link: interfaces taken or dropped, peers found |
| `MYCEL_PATH_DEBUG` | `1` | Every path's estimates, each time a path is selected |
| `MYCEL_CALL_DEBUG` | any value | Each call leg's path and round-trip time, once a second |
| `MYCEL_VIDEO_DEBUG` | any value | Video frames sent, keyframe requests, encoder events and the rate controller's state |

### Link logs

`MYCEL_BLE_LOG` sets how much the Bluetooth link logs.

| Level | Logs |
|---|---|
| `0` | Nothing |
| `1` | Connection attempts and results, channels opening and closing, radio changes |
| `2` | Also every input to the link's state machine and every command |

These lines name nearby devices and say when they came and went, so a
release build logs none of them unless asked.

When the app writes its log to `mycel.log` and `MYCEL_BLE_LOG` is not set,
it takes the level from two other places:

- A file named `link-diagnostics` in the data folder, holding `1` or `2`.
  An empty file means 1. This is the way to turn the log on where no
  variable can be set, such as an iPhone.
- A debug build with no such file uses level 1.

## Tests, benchmarks and the simulator

**None of these is a setting for running Mycel.** They are read by tests,
benchmarks, the simulator and the benchmark scripts.

### Tests

| Variable | Read by | Effect |
|---|---|---|
| `MYCEL_IFACE_TEST` | the `paths` and `sync` tests of `mycel-link-iface` | The interface to test on, in place of loopback. `paths` takes several, separated by commas |
| `MYCEL_WRITE_FIXTURES` | the `write_fixtures` test of `mycel-sync` | Any value: rewrite the Automerge change fixtures |
| `MYCEL_CONTACT` | the iOS UI tests in `apps/host/ios-uitests` | The name of the contact whose conversation the test opens; "Desk Test" by default |
| `MYCEL_REALTIME_THROTTLED_CHILD` | a `mycel-video` test | Internal: the test sets it on a copy of itself that it starts. Do not set it |

[TESTING.md](TESTING.md) describes the suites, and
[PLATFORMS.md](PLATFORMS.md) the iOS UI tests.

### Benchmarks

Two benchmarks in `mycel-node` are ignored tests, run by name:

```sh
MYCEL_BENCH_MESSAGES=100000 cargo test -p mycel-node --lib a_huge_chat -- --ignored --nocapture
MYCEL_BENCH_CHATS=200 MYCEL_BENCH_MESSAGES=1000 cargo test -p mycel-node --lib many_large_chats -- --ignored --nocapture
```

| Variable | Default | Effect |
|---|---|---|
| `MYCEL_BENCH_MESSAGES` | 100000 in `a_huge_chat`, 1000 in `many_large_chats` | Messages in each chat |
| `MYCEL_BENCH_CHATS` | 200 | Chats, in `many_large_chats` |
| `MYCEL_BENCH_ROUNDS` | 10 | Times the list of chats is read, in `many_large_chats` |
| `MYCEL_REPLAY` | the build under `target/` | The `dtn-replay` binary that `bench/run.py` and `bench/ablation.py` run |

[BENCHMARKS.md](BENCHMARKS.md) covers the store-and-forward benchmarks.

### Simulator

`mycel-sim` reads these. [SIMULATION.md](SIMULATION.md) explains the
scenarios they apply to.

| Variable | Values | Effect |
|---|---|---|
| `MYCEL_CORE` | `key=value` pairs: `every`, `far`, `hops`, `greet`, `fisheye`, `reduction` | Settings of the routing core in tier-2 scenarios |
| `MYCEL_DTN` | `key=value` pairs: `spray`, `gradient`, `copies`, `copies_small`, `room` | Settings of the store-and-forward carrier in tier-2 scenarios |
| `MYCEL_TRACE` | a contact trace file | The trace that `trace-replay` and `export-trace` use, in place of a synthetic one |
| `MYCEL_PINGS` | a directory of measured pings | Tier 2 uses the measured round-trip times in place of its latency model; `fit-latency` reads them |
| `MYCEL_SIM_BLE_QUEUE` | `radio` | Model Bluetooth with one queue for each radio, not one for each peer |
| `MYCEL_SIM_LINGER` | seconds | How long the mules wait before they walk, in `disaster-live`; 0 by default |
| `MYCEL_SIM_MEMLOG` | seconds | Log memory and live tasks that often during a tier-1 run |
| `MYCEL_SIM_TRACE` | any value | Print what the tier-1 lab is doing |
| `MYCEL_SIM_EVENTS` | any value | Print the count of each kind of event in a tier-2 run |

A pair that `MYCEL_CORE` or `MYCEL_DTN` does not know stops the run.

## Build scripts

These are read when building and packaging, not when Mycel runs.

- `scripts/package-mac.sh` reads `MYCEL_SIGN_IDENTITY`, `MYCEL_SIGN_KEYCHAIN`
  and the `MYCEL_NOTARY_*` variables to sign and notarise the Mac app. The
  script's header lists them.
- `scripts/package-android.sh` reads `MYCEL_ANDROID_SIGNING`, the folder
  that holds the release signing key (`~/.mycel-signing/android` by
  default), and honours `ANDROID_HOME`, `NDK_HOME` and `JAVA_HOME`.
- `scripts/remap-paths.sh` sets `MYCEL_INNER_RUSTC_WRAPPER` for its own
  use, to keep a `RUSTC_WRAPPER` that was already set. Do not set it.
- `.github/workflows/apps.yml` sets `TAURI_CLI`, the npm package and
  version of the Tauri command-line tool that its Linux and Windows jobs
  run.

[PLATFORMS.md](PLATFORMS.md) describes building each app.
