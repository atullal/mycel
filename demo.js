import * as A from "@automerge/automerge"

// 1. Alice creates a shared doc
let alice = A.from({ title: "Groceries", items: [], notes: "Buy for the week" })

// 2. Bob gets a copy (in a real app this travels over the network / a file)
let bob = A.load(A.save(alice))

// 3. Both edit OFFLINE, concurrently
alice = A.change(alice, "alice adds milk", d => {
  d.items.push({ name: "milk", done: false })
  A.splice(d, ["notes"], 0, 0, "URGENT: ")        // insert at start of text
  d.title = "Alice's Groceries"                     // conflicting field
})
bob = A.change(bob, "bob adds eggs", d => {
  d.items.push({ name: "eggs", done: false })
  A.splice(d, ["notes"], d.notes.length, 0, " (and snacks)") // append to text
  d.title = "Bob's Groceries"                       // conflicting field
})

// 4. Reconnect: merge both ways
const aliceMerged = A.merge(A.clone(alice), bob)
const bobMerged = A.merge(A.clone(bob), alice)

console.log("Merged doc:", JSON.stringify(aliceMerged, null, 2))
console.log("Both replicas identical:",
  JSON.stringify(aliceMerged) === JSON.stringify(bobMerged))
console.log("Conflicting values for title:", A.getConflicts(aliceMerged, "title"))

// 5. Full history is kept
console.log("History:", A.getHistory(aliceMerged).map(h => h.change.message))

// 6. Incremental sync protocol (what automerge-repo does under the hood)
let s1 = A.initSyncState(), s2 = A.initSyncState()
let src = A.clone(aliceMerged), carol = A.init(), msg, rounds = 0
do {
  ;[s1, msg] = A.generateSyncMessage(src, s1)
  if (msg) [carol, s2] = A.receiveSyncMessage(carol, s2, msg)
  ;[s2, msg] = A.generateSyncMessage(carol, s2)
  if (msg) [src, s1] = A.receiveSyncMessage(src, s1, msg)
  rounds++
} while (msg && rounds < 10)
console.log(`Carol synced from scratch in ${rounds} round(s):`, carol.items.map(i => i.name))
console.log("Saved size (bytes):", A.save(aliceMerged).length)
