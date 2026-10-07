//! Minimal fixed-size bitset for ancestor / validity sets over topo indices.

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BitSet(Vec<u64>);

impl BitSet {
    pub fn new(n: usize) -> Self {
        BitSet(vec![0; n.div_ceil(64)])
    }
    pub fn set(&mut self, i: usize) {
        self.0[i / 64] |= 1 << (i % 64);
    }
    pub fn get(&self, i: usize) -> bool {
        self.0.get(i / 64).is_some_and(|w| w & (1 << (i % 64)) != 0)
    }
    pub fn union_with(&mut self, other: &BitSet) {
        for (a, b) in self.0.iter_mut().zip(&other.0) {
            *a |= b;
        }
    }
    pub fn intersect(&self, other: &BitSet) -> BitSet {
        BitSet(self.0.iter().zip(&other.0).map(|(a, b)| a & b).collect())
    }
    /// Indices in ascending (= topological) order.
    pub fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        self.0.iter().enumerate().flat_map(|(wi, &w)| {
            (0..64).filter(move |b| w & (1 << b) != 0).map(move |b| wi * 64 + b)
        })
    }
}
