import { useMemo, useState } from "react";
import { useContacts, useMycel, useNearby, useNetwork, useProfile } from "@mycel/sdk/react";
import type { LinkStatus, NetworkMode, NetworkStatus, PathKind } from "@mycel/sdk";
import { initials, toneFor } from "./common.tsx";

const MODE: Record<NetworkMode, { name: string; text: string }> = {
  lan: {
    name: "Local only",
    text: "Same network, peer-to-peer Wi-Fi and Bluetooth. Never uses the internet.",
  },
  internet: {
    name: "All paths",
    text: "Everything local, plus encrypted internet relays for people who are elsewhere.",
  },
  local: {
    name: "This device only",
    text: "Not connecting to anyone. Used for testing.",
  },
};

const PATH: Record<PathKind, { name: string; text: string }> = {
  network: { name: "Same network", text: "Wi-Fi, Ethernet or a cable between the devices." },
  peerWifi: { name: "Peer-to-peer Wi-Fi", text: "Device to device, like AirDrop. Needs Wi-Fi on, but no network." },
  bluetooth: { name: "Bluetooth", text: "Slow but works with Wi-Fi off. Fine for messages, slow for big files." },
  relay: { name: "Internet relay", text: "Through an encrypted relay when you're on different networks." },
  wifiDirect: { name: "Wi-Fi Direct", text: "Device to device over Wi-Fi Direct or Wi-Fi Aware. No network needed." },
  uwb: { name: "UWB", text: "Ultra-wideband radio: short range, a few Mbit/s." },
  ieee802154: { name: "Thread / 802.15.4", text: "Low-power radio (Thread, 6LoWPAN): very slow, fine for messages." },
  ethernet: { name: "Cable", text: "A direct cable: Ethernet, Thunderbolt or USB." },
  other: { name: "Other link", text: "Another network interface on this device." },
};

/** One row per path: is it working, and how many devices it reaches. */
function pathRows(status: NetworkStatus): { kind: PathKind; label?: string | null; on: boolean; text: string }[] {
  const reach = (kind: PathKind) => status.peers.filter((p) => p.available.includes(kind)).length;
  const devices = (n: number) => (n === 1 ? "1 device" : `${n} devices`);
  const rows: { kind: PathKind; label?: string | null; on: boolean; text: string }[] = [
    {
      kind: "network",
      on: status.addresses.length > 0,
      text: status.addresses.length ? devices(reach("network")) : "Not connected to a network",
    },
  ];
  const link = (kind: PathKind): LinkStatus | undefined => status.links.find((l) => l.kind === kind);
  for (const kind of ["peerWifi", "bluetooth"] as PathKind[]) {
    const l = link(kind);
    rows.push(
      l
        ? { kind, on: l.active, text: l.active ? (l.peers === 0 && l.detail ? l.detail : devices(l.peers)) : (l.detail ?? "Not available") }
        : { kind, on: false, text: "Not available on this device" },
    );
  }
  // Any other radio or interface this device has (UWB, Wi-Fi Direct, a cable, ...)
  for (const l of status.links) {
    if (l.kind === "peerWifi" || l.kind === "bluetooth") continue;
    rows.push({
      kind: l.kind,
      label: l.label,
      on: l.active,
      text: l.active ? (l.peers === 0 && l.detail ? l.detail : devices(l.peers)) : (l.detail ?? "Not available"),
    });
  }
  rows.push(
    status.mode === "internet"
      ? { kind: "relay", on: true, text: "On when the internet is available" }
      : { kind: "relay", on: false, text: "Off (local only)" },
  );
  return rows;
}

type NodeState = "online" | "nearby" | "offline";

interface Node {
  id: string;
  name: string;
  state: NodeState;
}

function hash(s: string) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619);
  return (h >>> 0) / 4294967295;
}

const W = 340;
const H = 256;
const CX = W / 2;
const CY = H / 2 + 6;

/**
 * Your part of the network, drawn as hyphae: you at the root, a thread to each
 * person. Live connections carry a slow pulse.
 */
function Hyphae({ me, nodes }: { me: { id: string; name: string }; nodes: Node[] }) {
  const laid = useMemo(() => {
    const n = Math.max(nodes.length, 1);
    return nodes.map((node, i) => {
      const h = hash(node.id);
      const angle = -Math.PI / 2 + (i / n) * Math.PI * 2 + (h - 0.5) * 0.35;
      const r = (node.state === "offline" ? 106 : 94) + h * 12;
      const x = CX + Math.cos(angle) * r * 1.25;
      const y = CY + Math.sin(angle) * r * 0.74;
      // Bend each thread sideways a little so the web reads as grown, not drawn.
      const bend = (h - 0.5) * 60;
      const mx = (CX + x) / 2 - Math.sin(angle) * bend;
      const my = (CY + y) / 2 + Math.cos(angle) * bend;
      return { ...node, x, y, d: `M${CX} ${CY} Q${mx.toFixed(1)} ${my.toFixed(1)} ${x.toFixed(1)} ${y.toFixed(1)}` };
    });
  }, [nodes]);

  return (
    <svg className="hyphae" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`You and ${nodes.length} people`}>
      {laid.map((n) => (
        <g key={n.id} className={`hy-thread is-${n.state}`}>
          <path d={n.d} className="hy-line" />
          {n.state !== "offline" && <path d={n.d} className="hy-pulse" pathLength={100} style={{ animationDelay: `${hash(n.id + "p") * -4}s` }} />}
        </g>
      ))}
      {laid.map((n) => (
        <g key={n.id} className={`hy-node is-${n.state}`} transform={`translate(${n.x.toFixed(1)} ${n.y.toFixed(1)})`}>
          <title>{`${n.name}: ${n.state === "nearby" ? "on your network" : n.state}`}</title>
          <circle r="17" className={`tone-${toneFor(n.id)}`} />
          <text dy="4.2">{initials(n.name)}</text>
          <text className="hy-label" dy="33">
            {n.name.split(" ")[0]}
          </text>
        </g>
      ))}
      <g className="hy-me" transform={`translate(${CX} ${CY})`}>
        <circle r="28" className="hy-me-halo" />
        <circle r="22" />
        <text dy="5">{initials(me.name)}</text>
      </g>
    </svg>
  );
}

function ModeSwitch({ status }: { status: NetworkStatus }) {
  const mycel = useMycel();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  if (status.mode === "local") return null;
  const pick = async (mode: NetworkMode) => {
    setBusy(true);
    setErr(null);
    try {
      await mycel.network.setMode(mode);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  };
  const pending = status.nextMode !== status.mode;
  const native = mycel.transport.kind === "tauri";
  return (
    <section className="p-card">
      <h4>Connections</h4>
      <div className="p-seg" role="radiogroup" aria-label="Network mode">
        {(["internet", "lan"] as const).map((m) => (
          <button key={m} role="radio" aria-checked={status.nextMode === m} className={status.nextMode === m ? "is-on" : ""} disabled={busy} onClick={() => void pick(m)}>
            {MODE[m].name}
          </button>
        ))}
      </div>
      <p className="p-help p-mode-help">{MODE[status.nextMode].text}</p>
      {pending && (
        <div className="p-restart">
          <span>Restart Mycel to switch to “{MODE[status.nextMode].name}”.</span>
          {native ? (
            <button className="h-btn h-btn-primary h-btn-small" onClick={() => void mycel.network.restart()}>
              Restart now
            </button>
          ) : (
            <span className="p-help">Restart <code>mycel serve</code>.</span>
          )}
        </div>
      )}
      {err && <p className="p-error">{err}</p>}
    </section>
  );
}

export function NetworkPanel() {
  const { status, error } = useNetwork();
  const { contacts } = useContacts();
  const { nearby } = useNearby();
  const { profile } = useProfile();

  const nodes = useMemo<Node[]>(() => {
    const online = new Set(status?.onlinePeers ?? []);
    const list: Node[] = contacts.map((c) => ({
      id: c.id,
      name: c.name,
      state: c.nearby ? "nearby" : online.has(c.id) || c.online ? "online" : "offline",
    }));
    for (const n of nearby) if (!n.isContact) list.push({ id: n.id, name: n.name, state: "nearby" });
    return list;
  }, [status, contacts, nearby]);

  if (!status) return error ? <p className="p-error">{error.message}</p> : null;

  return (
    <div className="p-network">
      {profile && <Hyphae me={profile} nodes={nodes} />}
      <ul className="hy-legend" aria-label="Legend">
        <li className="is-nearby">On your network</li>
        <li className="is-online">Connected</li>
        <li className="is-offline">Offline</li>
      </ul>

      <dl className="p-stats">
        <div>
          <dt>Connected</dt>
          <dd>{status.onlinePeers.length}</dd>
        </div>
        <div>
          <dt>On your network</dt>
          <dd>{status.nearbyPeers}</dd>
        </div>
      </dl>

      <ModeSwitch status={status} />

      <section className="p-card">
        <h4>Paths</h4>
        <ul className="p-paths">
          {pathRows(status).map((r) => (
            <li key={`${r.kind}:${r.label ?? ""}`} className={r.on ? "is-on" : ""} title={PATH[r.kind].text}>
              <span className="p-path-dot" aria-hidden="true" />
              <span className="p-path-name">
                {PATH[r.kind].name}
                {r.label && <span className="p-path-label"> {r.label}</span>}
              </span>
              <span className="p-path-state">{r.text}</span>
            </li>
          ))}
        </ul>
      </section>

      {status.peers.length > 0 && (
        <section className="p-card">
          <h4>Talking to</h4>
          <ul className="p-paths">
            {status.peers.map((p) => (
              <li key={p.id} className={p.online ? "is-on" : ""}>
                <span className="p-path-dot" aria-hidden="true" />
                <span className="p-path-name">{p.name}</span>
                <span className="p-path-state">
                  {p.via ? `via ${PATH[p.via].name}` : p.online ? "reachable" : "offline"}
                  {p.available.length > 1 && ` · ${p.available.length} paths`}
                </span>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="p-card">
        <h4>Listening on</h4>
        {status.addresses.length ? (
          <ul className="p-addrs">
            {status.addresses.map((a) => (
              <li key={a}>
                <code>{a}</code>
              </li>
            ))}
          </ul>
        ) : (
          <p className="p-help">No local addresses yet.</p>
        )}
      </section>
    </div>
  );
}
