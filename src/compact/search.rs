//! The full-duplex search, over an interval.
//!
//! Each message does both jobs: it selects within the counterparty's
//! dissection and dissects further.  `L + 1` transactions locate the first
//! divergent step of a `b^L`-step trace, where a classical search would
//! take `2L`.
//!
//! What changed from the trace-tree version, and why it is the point of
//! Compact BitVMX II: a stage dissects the *live interval* and publishes
//! the `b - 1` interior states, rather than descending a tree of
//! publications and publishing a node's `b` children.
//!
//! The interval's endpoints carry inherited obligations -- the lower one
//! agreed, the upper one disagreed -- and that single fact removes three
//! obligations the tree had:
//!
//!   * no publication has to open from a parent node, so there is no M2;
//!   * the agreed lower endpoint is carried explicitly, so it cannot go
//!     missing at a subtree boundary;
//!   * `select` is TOTAL.  Where the tree returned `NothingToSelect` when
//!     the two vectors were equal -- a stall it then had to punish -- equal
//!     interior states here mean the disagreement is in the last
//!     subinterval, against the inherited upper endpoint.

use super::flatmerkle::StructuredFile;
use super::memory::NODE;

/// A state hash, as the trace carries it.
pub type State = [u8; NODE];

/// Who sends a stage.  Stage 1 is the prover's, and they alternate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Party {
    Prover,
    Challenger,
}

impl Party {
    pub fn of_stage(i: usize) -> Self {
        if i % 2 == 1 {
            Party::Prover
        } else {
            Party::Challenger
        }
    }

    pub fn other(self) -> Self {
        match self {
            Party::Prover => Party::Challenger,
            Party::Challenger => Party::Prover,
        }
    }
}

/// The live interval: `lo` is agreed, `hi` is disagreed.
///
/// That invariant is the whole search.  It holds at the start, where the
/// initial state is agreed by construction and the claimed result is not,
/// and `narrow` preserves it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interval {
    pub lo: usize,
    pub hi: usize,
}

impl Interval {
    pub fn len(&self) -> usize {
        self.hi - self.lo
    }

    pub fn is_single_step(&self) -> bool {
        self.len() == 1
    }

    /// The `b - 1` interior dissection points, in order.
    ///
    /// The endpoints are deliberately absent: they are inherited, not
    /// published, and publishing them would be the tree's mistake again.
    pub fn points(&self, b: usize) -> Vec<usize> {
        let step = self.len() / b;
        assert!(step >= 1, "interval {:?} is too short to dissect into {}", self, b);
        assert_eq!(self.len() % b, 0, "interval {:?} does not divide by {}", self, b);
        (1..b).map(|k| self.lo + k * step).collect()
    }

    /// The `k`-th subinterval, `k` in `0..b`.
    pub fn subinterval(&self, b: usize, k: usize) -> Interval {
        assert!(k < b);
        let pts = self.points(b);
        Interval {
            lo: if k == 0 { self.lo } else { pts[k - 1] },
            hi: if k == b - 1 { self.hi } else { pts[k] },
        }
    }
}

/// The selection rule, and it is total.
///
/// `published` and `own` are the `b - 1` interior states.  Returns the
/// index of the subinterval that inherits the disagreement:
///
///   * the least `i` at which the two differ -- then the point before it
///     agrees (or the inherited `lo` does), and the point at `i` does not;
///   * `b - 1` when they agree everywhere -- then the last interior point
///     agrees and the inherited `hi` does not.
///
/// There is no equal-vector stall, and so no option is needed to punish
/// one.  Compare the trace-tree version, which returned `None` here.
pub fn select(published: &[State], own: &[State]) -> usize {
    assert_eq!(published.len(), own.len());
    published
        .iter()
        .zip(own)
        .position(|(p, o)| p != o)
        .unwrap_or(published.len())
}

/// One stage: a selection over the previous dissection, and a dissection
/// of the interval that selection named.
#[derive(Clone, Debug)]
pub struct Stage {
    pub index: usize,
    pub sender: Party,
    pub selection: Option<usize>,
    pub interval: Interval,
    pub publication: Option<StructuredFile>,
}

/// What the search produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// The single step the search isolated: `[step, step + 1]`.
    pub step: usize,
    /// The selections, in order.
    pub digits: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SearchError {
    /// The claimed results agree, so there is no dispute to run.
    ResultsAgree,
    /// The trace length is not a power of the branching factor.
    NotDivisible { steps: usize, b: usize },
}

/// How many narrowing levels a `steps`-step trace needs at branching `b`.
pub fn levels(steps: usize, b: usize) -> u32 {
    let mut l = 0u32;
    let mut n = 1usize;
    while n < steps {
        n *= b;
        l += 1;
    }
    l
}

/// Run the whole search between two traces.
///
/// A trace is the state after each step: `trace[j]` is the state at step
/// `j`, so `trace[0]` is the agreed initial state.  Both parties follow
/// the protocol here; dishonest play is the subject of the soundness
/// argument, not of this function.
pub fn run(
    prover: &[State],
    challenger: &[State],
    b: usize,
) -> Result<(Vec<Stage>, Outcome), SearchError> {
    assert_eq!(prover.len(), challenger.len());
    let steps = prover.len() - 1;
    if prover[steps] == challenger[steps] {
        return Err(SearchError::ResultsAgree);
    }
    let l = levels(steps, b);
    if b.pow(l) != steps {
        return Err(SearchError::NotDivisible { steps, b });
    }

    let trace = |p: Party| match p {
        Party::Prover => prover,
        Party::Challenger => challenger,
    };

    let mut stages: Vec<Stage> = Vec::with_capacity(l as usize + 1);
    let mut digits: Vec<usize> = Vec::with_capacity(l as usize);
    let mut iv = Interval { lo: 0, hi: steps };

    for i in 1..=(l as usize) {
        let sender = Party::of_stage(i);
        // The sender dissects the live interval.  Its own states at the
        // interior points are what it publishes.
        let selection = if i == 1 {
            None
        } else {
            // The counterparty published at stage i-1; this sender selects.
            let prev = &stages[i - 2];
            let pts = prev.interval.points(b);
            let published: Vec<State> =
                pts.iter().map(|&t| trace(sender.other())[t]).collect();
            let own: Vec<State> = pts.iter().map(|&t| trace(sender)[t]).collect();
            let k = select(&published, &own);
            digits.push(k);
            iv = prev.interval.subinterval(b, k);
            Some(k)
        };
        stages.push(Stage {
            index: i,
            sender,
            selection,
            interval: iv,
            publication: None, // the caller builds the file; see `checkpoints`
        });
    }

    // The trailing selection names the single step.
    let last = stages.last().expect("at least one stage").clone();
    let pts = last.interval.points(b);
    let sender = Party::of_stage(l as usize + 1);
    let published: Vec<State> = pts.iter().map(|&t| trace(sender.other())[t]).collect();
    let own: Vec<State> = pts.iter().map(|&t| trace(sender)[t]).collect();
    let k = select(&published, &own);
    digits.push(k);
    let final_iv = last.interval.subinterval(b, k);
    debug_assert!(final_iv.is_single_step(), "{:?} should be one step", final_iv);

    Ok((
        stages,
        Outcome {
            step: final_iv.lo,
            digits,
        },
    ))
}

/// A dispute boundary: the step the endgame adjudicates, and the two
/// values the parties hold for it.
#[derive(Clone, Debug)]
pub struct Boundary {
    pub step: usize,
    pub pre_state: State,
    pub prover_post: State,
    pub challenger_post: State,
}

/// Read the boundary out of a finished search.
///
/// Unlike the trace-tree version this needs no special case at a subtree
/// edge: the pre-state is the interval's own agreed lower endpoint.
pub fn boundary(prover: &[State], challenger: &[State], out: &Outcome) -> Boundary {
    let j = out.step;
    Boundary {
        step: j,
        pre_state: prover[j],
        prover_post: prover[j + 1],
        challenger_post: challenger[j + 1],
    }
}
