use crate::GenerateError;
use regex_automata::nfa::thompson::{NFA, State, WhichCaptures};
use serde::Serialize;
use serde_json::json;

const MAX_STATES: usize = 65_536;
const MAX_EDGES: usize = 262_144;
const MAX_PATTERN_BYTES: usize = 32_768;

#[derive(Serialize)]
pub(crate) struct Program {
    start: usize,
    states: Vec<serde_json::Value>,
}

#[derive(Default)]
pub(crate) struct Compiler {
    states: usize,
    edges: usize,
    pub unicode: bool,
}

impl Compiler {
    pub fn compile(&mut self, pattern: &str) -> Result<Program, GenerateError> {
        if pattern.len() > MAX_PATTERN_BYTES {
            return Err(GenerateError::Budget);
        }
        let nfa = NFA::compiler()
            .configure(
                NFA::config()
                    .which_captures(WhichCaptures::None)
                    .nfa_size_limit(Some(1024 * 1024)),
            )
            .build(pattern)
            .map_err(|_| GenerateError::Pattern)?;
        self.states = self
            .states
            .checked_add(nfa.states().len())
            .ok_or(GenerateError::Budget)?;
        if self.states > MAX_STATES {
            return Err(GenerateError::Budget);
        }
        let mut states = Vec::with_capacity(nfa.states().len());
        for state in nfa.states() {
            let (value, edges) = match state {
                State::ByteRange { trans } => (
                    json!([0, [[trans.start, trans.end, trans.next.as_usize()]]]),
                    1,
                ),
                State::Sparse(sparse) => (
                    json!([
                        0,
                        sparse
                            .transitions
                            .iter()
                            .map(|t| (t.start, t.end, t.next.as_usize()))
                            .collect::<Vec<_>>()
                    ]),
                    sparse.transitions.len(),
                ),
                State::Dense(dense) => {
                    let mut ranges: Vec<(usize, usize, usize)> = Vec::new();
                    for (byte, next) in dense.transitions.iter().enumerate() {
                        if next.as_usize() == 0 {
                            continue;
                        }
                        if let Some(last) = ranges.last_mut()
                            && last.1 + 1 == byte
                            && last.2 == next.as_usize()
                        {
                            last.1 = byte;
                        } else {
                            ranges.push((byte, byte, next.as_usize()));
                        }
                    }
                    let edges = ranges.len();
                    (json!([0, ranges]), edges)
                }
                State::Look { look, next } => {
                    let tag = (*look as u32).trailing_zeros();
                    self.unicode |= matches!(tag, 8 | 9 | 12 | 13 | 16 | 17);
                    (json!([1, tag, next.as_usize()]), 1)
                }
                State::Union { alternates } => (
                    json!([
                        2,
                        alternates
                            .iter()
                            .map(|id| id.as_usize())
                            .collect::<Vec<_>>()
                    ]),
                    alternates.len(),
                ),
                State::BinaryUnion { alt1, alt2 } => {
                    (json!([2, [alt1.as_usize(), alt2.as_usize()]]), 2)
                }
                State::Capture { next, .. } => (json!([2, [next.as_usize()]]), 1),
                State::Fail => (json!([3]), 0),
                State::Match { .. } => (json!([4]), 0),
            };
            self.edges = self.edges.checked_add(edges).ok_or(GenerateError::Budget)?;
            if self.edges > MAX_EDGES {
                return Err(GenerateError::Budget);
            }
            states.push(value);
        }
        Ok(Program {
            start: nfa.start_unanchored().as_usize(),
            states,
        })
    }
}

pub(crate) fn word_ranges() -> Result<Vec<(u32, u32)>, GenerateError> {
    let hir = regex_syntax::Parser::new()
        .parse(r"\w")
        .map_err(|_| GenerateError::Pattern)?;
    match hir.kind() {
        regex_syntax::hir::HirKind::Class(regex_syntax::hir::Class::Unicode(class)) => Ok(class
            .ranges()
            .iter()
            .map(|range| (range.start() as u32, range.end() as u32))
            .collect()),
        _ => Err(GenerateError::Pattern),
    }
}
