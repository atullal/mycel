# Testing Mycel on two Macs, with no internet

This walks you through installing the Mycel app on two laptops and messaging
between them over the local network only. No accounts, no server, no internet.

> Mycel is pre-release and **not audited**. Don't use it for real secrets yet.

## What you need

- Two Macs running macOS 11 or later, on the **same Wi-Fi or wired network**.
- The app from `dist-release/` (built by `scripts/package-mac.sh`):

  | File | Runs on |
  |---|---|
  | `Mycel_0.1.0_aarch64.dmg`, `Mycel_0.1.0_aarch64.app.zip`, `aarch64/Mycel.app` | Apple silicon Macs (M1 and later) |
  | `Mycel_0.1.0_universal.dmg`, `Mycel_0.1.0_universal.app.zip`, `universal/Mycel.app` | Apple silicon **and** Intel Macs |

  The three files in a row are the same app packaged three ways; use whichever
  is easiest to copy. Not sure which Mac you have? Apple menu > About This Mac:
  "Chip: Apple M…" is Apple silicon, "Processor: Intel" is Intel. When in
  doubt, use the universal build.

## 1. Install on both laptops

1. Copy the `.dmg` (or the `.app.zip`) to the other laptop: AirDrop, a USB
   stick, or a shared folder all work.
2. Open the `.dmg` and drag **Mycel** into **Applications**
   (or double-click the `.zip` and drag the resulting `Mycel.app` to Applications).
3. **First launch of an unsigned app.** The app isn't signed by an Apple
   developer ID, so Gatekeeper blocks a plain double-click. Pick one:
   - In Finder, **right-click (or Control-click) Mycel > Open**, then **Open**
     in the dialog. On recent macOS, if there is no Open button: try to open it
     once, then go to **System Settings > Privacy & Security**, scroll down to
     *"Mycel" was blocked…* and click **Open Anyway**.
   - Or, in Terminal, remove the quarantine flag once:

     ```sh
     xattr -dr com.apple.quarantine /Applications/Mycel.app
     ```

   On the Mac that built the app, none of this is needed.
4. **Allow the network prompts.** On first launch macOS may ask:
   - *"Allow Mycel to find devices on local networks?"* → **Allow**.
     (If you missed it: System Settings > Privacy & Security > Local Network >
     turn **Mycel** on, then quit and reopen Mycel.)
   - *"Do you want the application Mycel to accept incoming network
     connections?"* (only if the macOS firewall is on) → **Allow**.
     (If you missed it: System Settings > Network > Firewall > Options… >
     set Mycel to *Allow incoming connections*.) Because the app is unsigned,
     macOS may ask again after you replace the app with a new build.

   - *"Mycel would like to use Bluetooth"* → **Allow** (the Bluetooth path;
     System Settings > Privacy & Security > Bluetooth if you missed it).
   - When you first attach a file from Desktop, Documents or Downloads, macOS
     may ask to let Mycel read that folder → **Allow**.

   Without the network permissions the laptops can't see or reach each other.

5. **Name each laptop.** A new profile is called "Anonymous", so both laptops
   start with the same name. Click your avatar at the bottom of the left rail
   (**Profile**) and set a name you'll recognise, e.g. "Laptop A" and
   "Laptop B". The window title shows it too.

## 2. Make sure there's no internet (optional, but that's the point)

By default Mycel uses **every path** it has (the Network panel calls this
*All paths*): the same network, peer-to-peer Wi-Fi, Bluetooth, and encrypted
internet relays when the internet is there. None of the local paths need the
internet. To be strict about it, open **Network** in the left rail, pick
**Local only** and click **Restart now**: Mycel then never contacts the
internet at all.

To prove it, cut the internet while keeping the two Macs on one local network:

- **Unplug the router's WAN / internet cable** (or disable its uplink); the Wi-Fi
  keeps working as a local network.
- Or use a **phone hotspot with mobile data turned off**: both laptops join the
  hotspot's Wi-Fi, the phone gives out local addresses but has no internet.
  (iPhone: Settings > Cellular > Cellular Data off, keep Personal Hotspot on.
  Some phones turn the hotspot off without data; Android usually doesn't.)
- Or connect the two Macs **directly**: a Thunderbolt/USB-C cable (Thunderbolt
  Bridge appears automatically) or an Ethernet cable between them. macOS gives
  both a `169.254.x.x` link-local address and mDNS works across it.

Check: open a website in Safari on both Macs; it should fail.

## 3. Add each other

Pick either way:

- **Nearby (easiest).** Click the **Nearby** (radar) button in the left rail.
  Within a few seconds the other laptop appears by name. Click **Add**. Do this
  on one laptop or both; adding is enough for one side to start a chat.
- **Contact codes.** On laptop A: **Profile** > *Your contact code* > copy it
  (or show the QR code). Send it to laptop B any way you like (AirDrop, a USB
  stick, read it out). On laptop B: **Contacts** > *Add by contact code* >
  paste > Add. A contact code holds the person's keys and name, plus the
  laptop's current LAN addresses (the part after `@`). That means **contact
  codes work even on networks that block mDNS**, as long as the two laptops
  can reach each other's IP. If the address changes (a new network, a new
  DHCP lease), mDNS or a fresh code fixes it.

## 4. Send messages and files

1. In **Messaging**, click **New conversation** (the pencil button at the top of
   the list), pick the other laptop, and start the chat.
2. Type and press **Enter**. The mark next to your message (hover it for a
   label) goes from a clock (*saved on this device*) to ticks: *sent* (some other
   device, e.g. a keeper, holds a copy), *delivered* (everyone in the chat has
   it), *read* (everyone has opened the chat).
3. Try the rest: replies, reactions, edit (↑ on an empty composer edits your
   last message), delete, typing indicator, group chats with a third device.
4. **Files, any size:** click the paperclip (**Attach files**), drag files onto
   the conversation, or paste one. Folders and packages (`.pages`, `.app`…) are
   sent as a `.zip`. Files up to 16 MB are sent to the other laptop right away;
   bigger ones (multi-GB videos are fine) download when the other side clicks
   the download button, with a progress bar. An interrupted download resumes.

The **Network** button in the rail shows each path (same network, peer-to-peer
Wi-Fi, Bluetooth, internet relay), whether it's working, and which path each
person is reached by right now.

## 5. No network at all: peer-to-peer Wi-Fi and Bluetooth

The two laptops don't need to share a network. Try each step and watch the
**Network** panel's *Talking to* list say which path is used:

1. **Leave the Wi-Fi network, keep Wi-Fi on** (on both Macs: Wi-Fi menu >
   disconnect, or forget the network; unplug Ethernet). Mycel switches to
   **Peer-to-peer Wi-Fi**: the same Apple radio link AirDrop uses. Messages and
   files keep working, at Wi-Fi speed, within a few seconds. Range is roughly a
   room or two.
2. **Turn Wi-Fi off entirely** (keep Bluetooth on). Mycel falls back to
   **Bluetooth**. Messages still go through, but it's slow (roughly 15–60 KB/s):
   fine for text, slow for photos, impractical for big files. Range is about
   10 m.
3. **Turn Wi-Fi back on / rejoin the network.** Mycel moves back to the faster
   path by itself.

A transfer that's already running moves to the next path when the current one
dies (it pauses for about 5 seconds while the dead path is detected).

If a path doesn't come up: the Network panel's *Paths* list says why (e.g.
"Bluetooth is off", or the permission to allow). Peer-to-peer Wi-Fi and
Bluetooth are new and had only been tested on one Mac before this; if either
doesn't connect between your laptops, run Mycel from Terminal
(`MYCEL_AWDL_DEBUG=1 MYCEL_BLE_LOG=2 /Applications/Mycel.app/Contents/MacOS/mycel-host`)
and keep the log.

## 6. Offline delivery

1. Quit Mycel on laptop B (**Mycel > Quit Mycel**, or ⌘Q).
2. On laptop A, send a few messages to B. They keep the clock mark
   (*saved on this device*), because nobody else has a copy yet.
3. Reopen Mycel on laptop B. Within seconds of the two finding each other the
   messages arrive and A's ticks move to *delivered* (and *read* once B opens
   the chat).

Messages are stored on the sender until a recipient (or a keeper, below) gets
them, so the sender has to be running when the recipient comes back.

## 7. Optional: a keeper on a third machine

A *keeper* is an always-on device that holds encrypted copies of a
conversation and relays them to members who are offline. It can't read them.
With a keeper, A can send while B is offline, then quit; B still gets the
messages later from the keeper.

On a third Mac or Linux box on the same network, with this repository checked
out and Rust installed:

```sh
cargo build --release -p mycel-cli
./target/release/mycel keeper --data ~/.mycel-keeper --name "Keeper" --net lan
```

It prints a contact code. Then, on laptop A:

1. **Contacts** > *Add by contact code* > paste the keeper's code.
2. Open the conversation > the **Details** (or **Members**) button at the right
   of the conversation header > **Keepers** > **Add a keeper** > pick "Keeper".
   Only the conversation's creator (admin) can add keepers.

Now test: quit B, send from A (the mark becomes *sent* once the keeper has a
copy), quit A, open B: the messages should arrive from the keeper.

(The same `mycel` CLI can also be a full device without the app:
`mycel serve --data ~/.mycel-cli --name "Terminal" --net lan` and open
<http://127.0.0.1:7777>, or script it with `mycel call <command> '<json>'`.)

## Where data lives

| | |
|---|---|
| Identity key, messages, contacts | `~/Library/Application Support/dev.mycel.host/` (`identity.key`, `mycel.redb`) |
| Received files | inside the same folder |

The identity key **is** your account: anyone with `identity.key` can act as you.
There is no recovery if you delete it.

## Reset

Quit Mycel, then:

```sh
rm -rf ~/Library/Application\ Support/dev.mycel.host
```

The next launch creates a brand-new identity (named "Anonymous" again). Your
old contacts will see a new, different person.

## Running two copies on one Mac (for developers)

The app reads three environment variables, so you can run several instances
side by side, each with its own identity:

```sh
APP=/Applications/Mycel.app/Contents/MacOS/mycel-host
MYCEL_DATA_DIR=/tmp/mycel-a MYCEL_NAME="Laptop A" MYCEL_NET=lan "$APP" &
MYCEL_DATA_DIR=/tmp/mycel-b MYCEL_NAME="Laptop B" MYCEL_NET=lan "$APP" &
```

- `MYCEL_DATA_DIR`: data folder (default: the Application Support folder above).
- `MYCEL_NAME`: display name; if set, it replaces the saved name on every launch.
- `MYCEL_NET`: `internet` (every path, the default), `lan` (local paths only,
  never the internet) or `local` (this Mac only). Overrides the Network panel.
- `MYCEL_LINKS`: `all` (default), `none`, or a list of `awdl,ble`.
- `MYCEL_IP=0`: turn off ordinary Wi-Fi/Ethernet IP, leaving only peer-to-peer
  Wi-Fi and Bluetooth (to prove those paths work on their own).

## Troubleshooting

**The other laptop never shows up in Nearby.**
- Both Macs must be on the **same network and subnet**. Compare the first three
  numbers of the IP address (System Settings > Wi-Fi > Details > TCP/IP),
  e.g. both `192.168.1.x`. A Mac on Ethernet and one on the Wi-Fi of a
  different router won't see each other.
- **Guest Wi-Fi, hotel, office and campus networks** often turn on *client
  isolation* (devices can reach the internet but not each other) and block
  mDNS. Use a home network, a phone hotspot, or a direct cable instead.
- **Local Network permission**: System Settings > Privacy & Security > Local
  Network > Mycel must be **on**. Quit and reopen Mycel after changing it.
- **Firewall**: System Settings > Network > Firewall. Either turn it off for the
  test, or make sure Mycel is set to *Allow incoming connections*. "Block all
  incoming connections" must be off. Third-party firewalls (Little Snitch,
  LuLu, corporate endpoint software) need a rule allowing Mycel.
- **VPNs** (corporate VPN, iCloud Private Relay is fine, Tailscale/WireGuard
  "exit node", "block LAN traffic" options) can hide the local network.
  Disconnect the VPN for the test.
- Wait 10 to 20 seconds; mDNS announcements are periodic. Quitting and
  reopening Mycel on both sides forces fresh announcements.
- Still nothing? The network (or a firewall) is probably blocking mDNS
  (UDP port 5353 multicast). **Exchange contact codes instead**: they carry
  the laptop's IP addresses, so the laptops connect directly without
  discovery. If even that fails, the network blocks traffic between devices
  (client isolation). Switch networks: a phone hotspot or a direct cable between
  the two Macs is the most reliable. (Mycel's mDNS records aren't standard
  Bonjour services, so `dns-sd -B` won't list them; that's expected.)

### Message requests
If the other laptop starts a chat with you before you've added it as a
contact, the chat shows up as a **request**. Click **Accept** to reply (the
person is then added to your contacts), or **Decline** / **Block**. People
who aren't your contacts can't see your name or profile until you accept.

**"Mycel is damaged and can't be opened"** — this is Gatekeeper's quarantine on
a downloaded unsigned app, not real damage. Run
`xattr -dr com.apple.quarantine /Applications/Mycel.app`.

**"You can't open the application because it is not supported on this type of
Mac"** — you copied the Apple silicon build to an Intel Mac. Use the universal
build.

**Messages stuck on the clock mark or "sent"** — the other side is offline or unreachable. Check
the **Network** panel: the other laptop should be listed as *Connected* or *On
your network*. Messages are delivered automatically when it comes back.

**A second copy of Mycel on the same Mac exits immediately** — only one copy can
use a data folder at a time. Use `MYCEL_DATA_DIR` (above) for a second copy.

**See logs** — run the app from Terminal to see its log output:
`/Applications/Mycel.app/Contents/MacOS/mycel-host`.

## Building the app

On a Mac with Rust (`rustup`), Node.js 20+, Xcode Command Line Tools and the
Tauri CLI (`cargo install tauri-cli --version '^2' --locked`):

```sh
scripts/package-mac.sh               # this Mac's architecture
scripts/package-mac.sh --universal   # Apple silicon + Intel in one app
```

Results land in `dist-release/`.
