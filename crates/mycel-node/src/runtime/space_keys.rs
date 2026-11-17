//! Where this device replaces its keys on a schedule (TRUST.md §6): the
//! spaces it takes part in.
//!
//! A replica with a key policy publishes reader keys in its space and
//! rotates epochs by age (`mycel_sync::KeyPolicy`). Publishing is saying
//! something, signed, to every member. So the policy is on only where the
//! user takes part: in spaces this device made, in conversations from
//! contacts, and in requests once they are accepted. A message request that
//! was never accepted gets nothing back from this device, not even a
//! reader key.

use mycel_sync::KeyPolicy;
use mycel_trust::SpaceId;

use super::Runtime;

impl Runtime {
    /// This device takes part in `space` from now on.
    pub(super) fn use_reader_keys(&self, space: &SpaceId) {
        let authored = self.node.with_space(space, |r| r.set_key_policy(Some(KeyPolicy::default())));
        if matches!(authored, Ok(Some(_))) {
            // A reader key went out: push it.
            self.node.changed(*space);
        }
    }

    /// At startup: every stored space except the requests still waiting
    /// for an answer.
    pub(super) fn use_reader_keys_where_taking_part(&self) {
        let waiting = self.requests.lock().clone();
        for space in self.node.space_ids() {
            if !waiting.contains_key(&space) {
                self.use_reader_keys(&space);
            }
        }
    }
}
