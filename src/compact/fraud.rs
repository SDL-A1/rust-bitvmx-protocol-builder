//! M1: refuting a file that is not a canonical FlatMerkle file.
//!
//! The guarantee this rests on is the one that makes the whole
//! construction usable when the publisher is the adversary: for *every*
//! byte string a publisher might publish at the fixed size, an honest
//! opponent can prove in logarithmic space either the inclusion of any
//! element or the malformation of the file.  There is no string that is
//! hard to prove anything about.
//!
//! A fraud proof walks the same recursive fold an ordinary inclusion
//! proof walks, for some target index, so every checkpoint it uses is
//! bound to the digest exactly as it always is -- except that at the
//! levels it disputes, the checkpoint the recursion would fold in is
//! replaced by the bytes actually sitting in the file there.  It is
//! accepted only if the fold still reaches the digest, every disputed
//! level was genuinely on the target's own path, and at least one of
//! them genuinely disagreed.
//!
//! The subtlety, and the reason `anchored_levels` exists: a disputed
//! level whose checkpoint feeds no surviving compression call is a free
//! variable, and comparing against it proves nothing.  Such a level is
//! still substituted -- the fold has to reach the digest when an
//! ancestor is genuinely corrupt -- but a mismatch there is not counted.

use super::flatmerkle::{mid_block, Frame, MIN_ELEMENTS};
use super::sha256_core::{compress, length_padding_blocks, BLOCK_SIZE, STATE_SIZE};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Where an item sits in the file, and what it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Item {
    /// Data element `i`.
    Data { pos: usize, i: usize },
    /// The MID block closing `block(a, k)`.
    Mid { pos: usize, a: usize, k: u32 },
}

impl Item {
    pub fn pos(&self) -> usize {
        match self {
            Item::Data { pos, .. } | Item::Mid { pos, .. } => *pos,
        }
    }
}

/// The item order of a file of `n` elements, without hashing anything.
pub fn layout(n: usize) -> Vec<Item> {
    assert!(n.is_power_of_two() && n >= MIN_ELEMENTS);
    let l = n.trailing_zeros();
    let mut items = Vec::with_capacity(2 * n - 2);
    let mut pos = 0usize;

    fn block(items: &mut Vec<Item>, pos: &mut usize, a: usize, k: u32) {
        if k == 1 {
            items.push(Item::Data { pos: *pos, i: a });
            *pos += 1;
            items.push(Item::Data {
                pos: *pos,
                i: a + 1,
            });
            *pos += 1;
            items.push(Item::Mid { pos: *pos, a, k: 1 });
            *pos += 1;
        } else {
            let half = 1usize << (k - 1);
            block(items, pos, a, k - 1);
            block(items, pos, a + half, k - 1);
            items.push(Item::Mid { pos: *pos, a, k });
            *pos += 1;
        }
    }

    block(&mut items, &mut pos, 0, l - 1);
    block(&mut items, &mut pos, 1usize << (l - 1), l - 1);
    items
}

/// A MID whose contents disagree with the checkpoint they should carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    pub a: usize,
    pub k: u32,
    pub pos: usize,
    pub true_checkpoint: [u8; STATE_SIZE],
    pub actual_bytes: Vec<u8>,
}

/// One linear pass over the file.
#[derive(Clone, Debug)]
pub struct Scan {
    pub n: usize,
    pub levels: u32,
    pub raw: Vec<u8>,
    pub state_before: Vec<[u8; STATE_SIZE]>,
    pub state_after: Vec<[u8; STATE_SIZE]>,
    pub mid_pos: HashMap<(usize, u32), usize>,
    pub data_pos: HashMap<usize, usize>,
    pub checkpoint: HashMap<usize, [u8; STATE_SIZE]>,
    pub violations: Vec<Violation>,
}

impl Scan {
    pub fn prewrap_of(&self, a: usize, k: u32) -> [u8; STATE_SIZE] {
        self.state_before[self.mid_pos[&(a, k)]]
    }
    pub fn ending_of(&self, a: usize, k: u32) -> [u8; STATE_SIZE] {
        self.state_after[self.mid_pos[&(a, k)]]
    }
    pub fn data_of(&self, i: usize) -> Vec<u8> {
        let off = self.data_pos[&i] * BLOCK_SIZE;
        self.raw[off..off + BLOCK_SIZE].to_vec()
    }
    pub fn mid_bytes_of(&self, a: usize, k: u32) -> Vec<u8> {
        let off = self.mid_pos[&(a, k)] * BLOCK_SIZE;
        self.raw[off..off + BLOCK_SIZE].to_vec()
    }
}

/// Walk the file exactly as ordinary SHA-256 hashing does -- using its
/// *actual* bytes throughout, right or wrong, because that is what the
/// real digest computation does -- and record every MID that disagrees
/// with the checkpoint it should carry.
///
/// Continuing with the actual bytes after a violation, rather than with
/// the value that should have been there, is what lets one pass find
/// several independent violations without one masking another.
pub fn scan_for_violations(n: usize, raw: &[u8], frame: &Frame) -> Option<Scan> {
    if n < MIN_ELEMENTS || !n.is_power_of_two() {
        return None;
    }
    let items = layout(n);
    if raw.len() != items.len() * BLOCK_SIZE {
        return None;
    }
    let mut scan = Scan {
        n,
        levels: n.trailing_zeros(),
        raw: raw.to_vec(),
        state_before: vec![[0; STATE_SIZE]; items.len()],
        state_after: vec![[0; STATE_SIZE]; items.len()],
        mid_pos: HashMap::new(),
        data_pos: HashMap::new(),
        checkpoint: HashMap::new(),
        violations: Vec::new(),
    };

    let mut state = frame.iv();
    for it in &items {
        let pos = it.pos();
        scan.state_before[pos] = state;
        if let Item::Data { i, .. } = it {
            scan.data_pos.insert(*i, pos);
            scan.checkpoint.entry(*i).or_insert(state);
        }
        let off = pos * BLOCK_SIZE;
        let actual = &raw[off..off + BLOCK_SIZE];
        if let Item::Mid { a, k, .. } = it {
            scan.mid_pos.insert((*a, *k), pos);
            let ck = scan.checkpoint[a];
            if actual != mid_block(&ck).as_slice() {
                scan.violations.push(Violation {
                    a: *a,
                    k: *k,
                    pos,
                    true_checkpoint: ck,
                    actual_bytes: actual.to_vec(),
                });
            }
        }
        state = compress(&state, actual);
        scan.state_after[pos] = state;
    }
    Some(scan)
}

/// A target's own containing blocks: `block(a, k)` for every level with
/// `a <= target < a + 2^k`.
///
/// These are the only positions a proof anchored at `target` may
/// substitute.  A sibling block's own closing step is visited along the
/// path too, but substituting there would sever the target's own chain
/// from the digest and break binding.
pub fn self_positions(levels: u32, target: usize) -> Vec<(usize, u32)> {
    let half_top = 1usize << (levels - 1);
    let base = if target >= half_top { half_top } else { 0 };
    let mut out = Vec::new();
    let mut k = levels - 1;
    while k >= 1 {
        let width = 1usize << k;
        let a = base + ((target - base) / width) * width;
        out.push((a, k));
        k -= 1;
    }
    out
}

/// Which disputed levels have a checkpoint that still feeds a surviving
/// compression call, and so can be counted as a mismatch.
pub fn anchored_levels(
    levels: u32,
    target: usize,
    violated: &BTreeSet<(usize, u32)>,
    iv_fixed: bool,
) -> BTreeSet<(usize, u32)> {
    let mut out = BTreeSet::new();
    let mut prev = true;
    for k in 1..levels {
        let a = (target >> k) << k;
        let mut b = if k == 1 {
            // the base case consumes the checkpoint in C(ckpt, d0)
            // whether or not its closing fold is substituted
            true
        } else {
            !violated.contains(&(a, k)) || (((target >> (k - 1)) & 1) == 0 && prev)
        };
        if iv_fixed && k == levels - 1 && target < (1usize << (levels - 1)) {
            // the top-level left root's checkpoint is the frame's derived
            // constant, which the verifier computes itself
            b = true;
        }
        if b {
            out.insert((a, k));
        }
        prev = b;
    }
    out
}

/// The violations a proof anchored at `target` can actually prove.
pub fn provable_set(scan: &Scan, target: usize) -> Vec<(usize, u32)> {
    let reachable: BTreeSet<(usize, u32)> =
        self_positions(scan.levels, target).into_iter().collect();
    let found: BTreeSet<(usize, u32)> = scan.violations.iter().map(|v| (v.a, v.k)).collect();
    let mut v: Vec<(usize, u32)> = reachable.intersection(&found).copied().collect();
    v.sort_by_key(|(_, k)| *k);
    v
}

/// A target for which `provable_set` is always non-empty and always
/// yields an accepting proof, whatever else in the file is corrupt.
pub fn pick_provable_target(scan: &Scan) -> Option<usize> {
    scan.violations.iter().map(|v| v.a).max()
}

/// The proof itself: an ordinary inclusion-proof-shaped reveal path, plus
/// the real bytes at every disputed MID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FraudProof {
    pub n: usize,
    pub target: usize,
    pub violated: Vec<(usize, u32)>,
    pub d0: Vec<u8>,
    pub d1: Vec<u8>,
    pub reveals: Vec<[u8; STATE_SIZE]>,
    pub actual_mid_bytes: BTreeMap<(usize, u32), Vec<u8>>,
}

impl FraudProof {
    pub fn nbytes(&self) -> usize {
        2 * BLOCK_SIZE + self.reveals.len() * STATE_SIZE + self.violated.len() * BLOCK_SIZE
    }
}

pub fn build_fraud_proof(
    scan: &Scan,
    target: usize,
    violated: &[(usize, u32)],
) -> Option<FraudProof> {
    let l = scan.levels;
    let valid: BTreeSet<(usize, u32)> = self_positions(l, target).into_iter().collect();
    if violated.iter().any(|p| !valid.contains(p)) {
        return None; // not one of the target's own containing blocks
    }
    let half_top = 1usize << (l - 1);
    let mut reveals: Vec<[u8; STATE_SIZE]> = Vec::new();

    fn recurse(scan: &Scan, reveals: &mut Vec<[u8; STATE_SIZE]>, a: usize, k: u32, t: usize) {
        if k == 1 {
            return;
        }
        let half = 1usize << (k - 1);
        if t < a + half {
            recurse(scan, reveals, a, k - 1, t);
            reveals.push(scan.prewrap_of(a + half, k - 1));
        } else {
            reveals.push(scan.ending_of(a, k - 1));
            recurse(scan, reveals, a + half, k - 1, t);
        }
    }

    if target < half_top {
        recurse(scan, &mut reveals, 0, l - 1, target);
        reveals.push(scan.prewrap_of(half_top, l - 1));
    } else {
        reveals.push(scan.ending_of(0, l - 1));
        recurse(scan, &mut reveals, half_top, l - 1, target);
    }

    let a0 = target - (target % 2);
    let mut v = violated.to_vec();
    v.sort_unstable();
    let actual_mid_bytes = v
        .iter()
        .map(|(a, k)| ((*a, *k), scan.mid_bytes_of(*a, *k)))
        .collect();
    Some(FraudProof {
        n: scan.n,
        target,
        violated: v,
        d0: scan.data_of(a0),
        d1: scan.data_of(a0 + 1),
        reveals,
        actual_mid_bytes,
    })
}

/// Verify a malformation claim in `O(log N)` compressions.
pub fn verify_fraud_proof(
    n: usize,
    digest: &[u8; STATE_SIZE],
    fp: &FraudProof,
    frame: &Frame,
    iv_fixed: bool,
) -> bool {
    if n < MIN_ELEMENTS || !n.is_power_of_two() || fp.n != n || fp.target >= n {
        return false;
    }
    let l = n.trailing_zeros();
    if fp.d0.len() != BLOCK_SIZE || fp.d1.len() != BLOCK_SIZE || fp.reveals.len() != l as usize - 1
    {
        return false;
    }
    let violated: BTreeSet<(usize, u32)> = fp.violated.iter().copied().collect();
    if fp.actual_mid_bytes.keys().copied().collect::<BTreeSet<_>>() != violated {
        return false; // exactly one byte string per disputed level
    }
    if fp.actual_mid_bytes.values().any(|b| b.len() != BLOCK_SIZE) {
        return false;
    }

    let anchored = anchored_levels(l, fp.target, &violated, iv_fixed);
    let mut levels_reached: BTreeSet<(usize, u32)> = BTreeSet::new();
    let mut mismatch = false;
    let mut it = fp.reveals.iter();

    struct Ctx<'a> {
        fp: &'a FraudProof,
        violated: &'a BTreeSet<(usize, u32)>,
        anchored: &'a BTreeSet<(usize, u32)>,
        reached: &'a mut BTreeSet<(usize, u32)>,
        mismatch: &'a mut bool,
    }

    fn maybe_substitute(c: &mut Ctx, a: usize, k: u32, honest_closing: Vec<u8>) -> Vec<u8> {
        if c.violated.contains(&(a, k)) {
            c.reached.insert((a, k));
            let claimed = c.fp.actual_mid_bytes[&(a, k)].clone();
            if claimed != honest_closing && c.anchored.contains(&(a, k)) {
                *c.mismatch = true;
            }
            return claimed;
        }
        honest_closing
    }

    fn eval_block(
        c: &mut Ctx,
        it: &mut std::slice::Iter<'_, [u8; STATE_SIZE]>,
        a: usize,
        k: u32,
        target: usize,
        ckpt: &[u8; STATE_SIZE],
    ) -> Option<[u8; STATE_SIZE]> {
        if k == 1 {
            let s = compress(&compress(ckpt, &c.fp.d0), &c.fp.d1);
            let closing = maybe_substitute(c, a, k, mid_block(ckpt));
            return Some(compress(&s, &closing));
        }
        let half = 1usize << (k - 1);
        let right_end = if target < a + half {
            let left_end = eval_block(c, it, a, k - 1, target, ckpt)?;
            let sib_prewrap = it.next()?;
            // the sibling's own closing step is always canonical: never
            // substituted, or the target's chain is severed from the digest
            compress(sib_prewrap, &mid_block(&left_end))
        } else {
            let left_end = *it.next()?;
            eval_block(c, it, a + half, k - 1, target, &left_end)?
        };
        let closing = maybe_substitute(c, a, k, mid_block(ckpt));
        Some(compress(&right_end, &closing))
    }

    let half_top = 1usize << (l - 1);
    let raw_state = {
        let mut c = Ctx {
            fp,
            violated: &violated,
            anchored: &anchored,
            reached: &mut levels_reached,
            mismatch: &mut mismatch,
        };
        if fp.target < half_top {
            let y = match eval_block(&mut c, &mut it, 0, l - 1, fp.target, &frame.iv()) {
                Some(y) => y,
                None => return false,
            };
            let r2 = match it.next() {
                Some(r) => r,
                None => return false,
            };
            compress(r2, &mid_block(&y))
        } else {
            let seed = match it.next() {
                Some(r) => *r,
                None => return false,
            };
            match eval_block(&mut c, &mut it, half_top, l - 1, fp.target, &seed) {
                Some(s) => s,
                None => return false,
            }
        }
    };

    if it.next().is_some() {
        return false;
    }
    if levels_reached != violated {
        return false; // a claimed level was never on the target's own path
    }

    let pad = length_padding_blocks(frame.hashed_len(n));
    let mut fstate = raw_state;
    for blk in pad.chunks(BLOCK_SIZE) {
        fstate = compress(&fstate, blk);
    }
    if &fstate != digest {
        // the reveal path does not fold to the real digest, so nothing
        // here is proven: reject as a dishonest claim, not as evidence
        return false;
    }
    mismatch
}
