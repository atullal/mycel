import { useMemo } from "react";
import { useContacts, useNearby, useNetwork, useProfile } from "@mycel/sdk/react";
import type { NetworkMode } from "@mycel/sdk";
import { initials, toneFor } from "./common.tsx";

const MODE: Record<NetworkMode, { name: string; text: string }> = {
  lan: {
    name: "Local network",
    text: "Finds people on the same Wi-Fi or wired network and talks to them directly. No internet needed.",
  },
  internet: {
    name: "Local network and internet",
    text: "Talks directly on your local network, and through encrypted relays when people are elsewhere.",
  },
  local: {
    name: "This device only",
    text: "Not connecting to anyone. Used for testing.",
  },
};

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
  const mode = MODE[status.mode];

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

      <section className="p-card">
        <h4>{mode.name}</h4>
        <p className="p-help">{mode.text}</p>
      </section>

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
