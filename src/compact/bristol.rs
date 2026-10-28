//! Bristol-fashion circuits, as `compact/circuits/emit.py` writes them.
//!
//! Three gate kinds and nothing else: `XOR` and `INV`, which are free
//! under free-XOR, and `AND`, which costs two ciphertexts.  The circuits
//! themselves are built and measured in the paper repository -- a step,
//! a SHA-256 compression, and the gated form of each -- and arrive here
//! as files, because a second implementation of a RISC-V CPU is a second
//! chance to be wrong about one.
//!
//! The format:
//!
//! ```text
//! <gates> <wires>
//! <n> <input sizes...>
//! <n> <output sizes...>
//! <blank>
//! <arity> 1 <in...> <out> <KIND>
//! ```
//!
//! Outputs are the top wires, the first output highest: output `k` is
//! wire `n_wires - 1 - k`.

use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    Xor { a: usize, b: usize, out: usize },
    Inv { a: usize, out: usize },
    And { a: usize, b: usize, out: usize },
}

impl Gate {
    pub fn out(&self) -> usize {
        match self {
            Gate::Xor { out, .. } | Gate::Inv { out, .. } | Gate::And { out, .. } => *out,
        }
    }
}

#[derive(Debug)]
pub enum ParseError {
    Header(String),
    Gate {
        line: usize,
        why: String,
    },
    Wire {
        line: usize,
        wire: usize,
        n_wires: usize,
    },
    OutputsNotOnTop,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Header(s) => write!(f, "bad header: {s}"),
            ParseError::Gate { line, why } => write!(f, "line {line}: {why}"),
            ParseError::Wire {
                line,
                wire,
                n_wires,
            } => write!(f, "line {line}: wire {wire} is beyond {n_wires}"),
            ParseError::OutputsNotOnTop => {
                write!(f, "the declared outputs are not the top wires")
            }
        }
    }
}

impl std::error::Error for ParseError {}

#[derive(Clone, Debug)]
pub struct Circuit {
    pub gates: Vec<Gate>,
    pub n_wires: usize,
    pub n_inputs: usize,
    pub n_outputs: usize,
}

impl Circuit {
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        let mut lines = s.lines();
        let nums = |l: Option<&str>, what: &str| -> Result<Vec<usize>, ParseError> {
            l.ok_or_else(|| ParseError::Header(format!("missing {what}")))?
                .split_whitespace()
                .map(|t| {
                    t.parse::<usize>()
                        .map_err(|_| ParseError::Header(format!("{what}: {t:?}")))
                })
                .collect()
        };
        let head = nums(lines.next(), "gate and wire counts")?;
        let ins = nums(lines.next(), "input sizes")?;
        let outs = nums(lines.next(), "output sizes")?;
        if head.len() != 2 {
            return Err(ParseError::Header("want <gates> <wires>".into()));
        }
        let (n_gates, n_wires) = (head[0], head[1]);
        let count = |v: &[usize]| -> Result<usize, ParseError> {
            let k = *v
                .first()
                .ok_or_else(|| ParseError::Header("empty".into()))?;
            if v.len() != k + 1 {
                return Err(ParseError::Header(format!(
                    "{k} sizes, {} given",
                    v.len() - 1
                )));
            }
            Ok(v[1..].iter().sum())
        };
        let n_inputs = count(&ins)?;
        let n_outputs = count(&outs)?;

        let mut gates = Vec::with_capacity(n_gates);
        for (i, raw) in lines.enumerate() {
            if raw.trim().is_empty() {
                continue;
            }
            let line = i + 4;
            let t: Vec<&str> = raw.split_whitespace().collect();
            let bad = |why: &str| ParseError::Gate {
                line,
                why: why.to_string(),
            };
            if t.len() < 4 {
                return Err(bad("too short"));
            }
            let arity: usize = t[0].parse().map_err(|_| bad("arity"))?;
            // <arity> <n_outputs> <in...> <out> <KIND>
            if t.len() != arity + 4 {
                return Err(bad("arity does not match the wires given"));
            }
            let w = |k: usize| -> Result<usize, ParseError> {
                let x: usize = t[k].parse().map_err(|_| bad("wire"))?;
                if x >= n_wires {
                    return Err(ParseError::Wire {
                        line,
                        wire: x,
                        n_wires,
                    });
                }
                Ok(x)
            };
            let out = w(arity + 2)?;
            gates.push(match (t[arity + 3], arity) {
                ("XOR", 2) => Gate::Xor {
                    a: w(2)?,
                    b: w(3)?,
                    out,
                },
                ("AND", 2) => Gate::And {
                    a: w(2)?,
                    b: w(3)?,
                    out,
                },
                ("INV", 1) => Gate::Inv { a: w(2)?, out },
                (k, n) => return Err(bad(&format!("{k} of arity {n}"))),
            });
        }
        if gates.len() != n_gates {
            return Err(ParseError::Header(format!(
                "header says {n_gates} gates, file has {}",
                gates.len()
            )));
        }
        let c = Circuit {
            gates,
            n_wires,
            n_inputs,
            n_outputs,
        };
        // The convention the loader depends on, checked rather than assumed.
        if n_outputs > n_wires
            || c.gates
                .last()
                .map(|g| g.out() != n_wires - 1)
                .unwrap_or(true)
        {
            return Err(ParseError::OutputsNotOnTop);
        }
        Ok(c)
    }

    /// Output `k` lives on this wire.  The first output is the top wire.
    pub fn output_wire(&self, k: usize) -> usize {
        self.n_wires - 1 - k
    }

    pub fn and_count(&self) -> usize {
        self.gates
            .iter()
            .filter(|g| matches!(g, Gate::And { .. }))
            .count()
    }

    /// Evaluate in the clear.  Returns every wire, so that a garbled
    /// evaluation can be checked against it wire by wire.
    pub fn eval(&self, inputs: &[bool]) -> Vec<bool> {
        assert_eq!(inputs.len(), self.n_inputs, "input width");
        let mut w = vec![false; self.n_wires];
        w[..inputs.len()].copy_from_slice(inputs);
        for g in &self.gates {
            match *g {
                Gate::Xor { a, b, out } => w[out] = w[a] ^ w[b],
                Gate::Inv { a, out } => w[out] = !w[a],
                Gate::And { a, b, out } => w[out] = w[a] & w[b],
            }
        }
        w
    }

    pub fn outputs(&self, wires: &[bool]) -> Vec<bool> {
        (0..self.n_outputs)
            .map(|k| wires[self.output_wire(k)])
            .collect()
    }
}
