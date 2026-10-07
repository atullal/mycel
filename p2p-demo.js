import { Repo } from "@automerge/automerge-repo"
import { MessageChannelNetworkAdapter as MC } from "@automerge/automerge-repo-network-messagechannel"

// Topology:  alice <--> relay <--> bob   (alice and bob are NOT directly connected)
const ab = new MessageChannel(), rb = new MessageChannel()
const alice = new Repo({ peerId: "alice", network: [new MC(ab.port1)] })
const relay = new Repo({
  peerId: "relay",
  network: [new MC(ab.port2), new MC(rb.port1)],
  // relay should not push docs to everyone, but still answers requests
  shareConfig: { announce: async () => false, access: async () => true },
})
// Bob just *claims* to be "bob" -- nothing verifies it
const bob = new Repo({ peerId: "bob", network: [new MC(rb.port2)] })

await new Promise(r => setTimeout(r, 200))
console.log("relay sees peers:", relay.peers)

const h = alice.create({ msg: "hello from alice" })
console.log("doc url (the only 'secret'):", h.url)

const bh = await bob.find(h.url)            // bob only knows the URL
console.log("bob got:", bh.doc())

bh.change(d => { d.reply = "hi alice, from bob" })
await new Promise(r => setTimeout(r, 300))
console.log("alice now sees:", h.doc())
process.exit(0)
