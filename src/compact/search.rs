//! The full-duplex search.
//!
//! Each message does both jobs: it selects within the counterparty's
//! dissection and dissects further.  `L + 1` transactions locate the
//! first divergent step of a `b^L`-step trace, where a classical search
//! would take `2L`.

use super::flatmerkle::StructuredFile;
use super::tracetree::{Node, TraceTree};

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

/// One stage: a selection over the previous publication, and a
/// publication of the node that selection names.
///
/// Stage 1 carries no selection; stage `L + 1` carries no publication,
/// because its selection names a leaf (Remark 5.3).
#[derive(Clone, Debug)]
pub struct Stage {
    pub index: usize,
    pub sender: Party,
    pub selection: Option<usize>,
    pub publication: Option<StructuredFile>,
    /// The node the publication lists the children of.
    pub node: Option<(u32, usize)>,
}

/// The selection rule: the least index at which the counterparty's
/// published children differ from the sender's own values for the same
/// node.
///
/// Returns `None` only when the two vectors are equal, which the sender
/// answers by disputing (M4) rather than selecting.
pub fn select(published: &[Node], own: &[Node]) -> Option<usize> {
    assert_eq!(published.len(), own.len());
    published.iter().zip(own).position(|(c, m)| c != m)
}

/// What the search produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// The leaf the search named.
    pub step: usize,
    /// The digits, most significant first.
    pub digits: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SearchError {
    /// The two parties published the same vector: there is nothing to
    /// select, and the sender refutes under M4 instead.
    NothingToSelect { stage: usize },
    /// The roots agree, so there is no dispute to run.
    RootsAgree,
}

/// Run the whole search between two trace trees.
///
/// Both parties follow the protocol here; dishonest play is the subject
/// of the soundness argument, not of this function.
pub fn run(
    prover: &TraceTree,
    challenger: &TraceTree,
) -> Result<(Vec<Stage>, Outcome), SearchError> {
    assert_eq!(prover.b, challenger.b);
    assert_eq!(prover.levels, challenger.levels);
    if prover.root() == challenger.root() {
        return Err(SearchError::RootsAgree);
    }
    let l = prover.levels;

    let tree = |p: Party| match p {
        Party::Prover => prover,
        Party::Challenger => challenger,
    };

    let mut stages: Vec<Stage> = Vec::with_capacity(l as usize + 1);
    let mut digits: Vec<usize> = Vec::with_capacity(l as usize);

    // Stage 1: the prover dissects the root.  No selection to make.
    stages.push(Stage {
        index: 1,
        sender: Party::Prover,
        selection: None,
        publication: Some(prover.publication_of(0, 0)),
        node: Some((0, 0)),
    });

    for i in 2..=(l as usize + 1) {
        let sender = Party::of_stage(i);
        let prev = stages.last().expect("a previous stage");

        // the node the previous stage dissected, and what it listed
        let (pd, pj) = prev.node.expect("every stage before the last dissects");
        let published = tree(sender.other()).children(pd, pj);
        let own = tree(sender).children(pd, pj);

        let k = match select(&published, &own) {
            Some(k) => k,
            None => return Err(SearchError::NothingToSelect { stage: i }),
        };
        digits.push(k);

        // the node that selection names
        let d = pd + 1;
        let j = pj * prover.b + k;

        let publication = if d < l {
            Some(tree(sender).publication_of(d, j))
        } else {
            None // stage L+1 names a leaf
        };
        stages.push(Stage {
            index: i,
            sender,
            selection: Some(k),
            publication,
            node: if d < l { Some((d, j)) } else { None },
        });
    }

    let mut step = 0usize;
    for k in &digits {
        step = step * prover.b + k;
    }
    Ok((stages, Outcome { step, digits }))
}

/// A dispute boundary: the step the endgame adjudicates, and the two
/// values the parties hold for it.
#[derive(Clone, Debug)]
pub struct Boundary {
    pub step: usize,
    pub pre_state: Node,
    pub prover_post: Node,
    pub challenger_post: Node,
}

/// Read the boundary out of a finished search.
pub fn boundary(prover: &TraceTree, challenger: &TraceTree, out: &Outcome) -> Boundary {
    let j = out.step;
    assert!(j > 0, "the search cannot name step zero as divergent");
    Boundary {
        step: j,
        pre_state: prover.leaves()[j - 1],
        prover_post: prover.leaves()[j],
        challenger_post: challenger.leaves()[j],
    }
}
