//! Append-only, hash-chained audit log (FR-AUD-1/2).
//!
//! One JSON object per line: `{"seq":n,"ts":unix,"kind":..,"data":..,"prev":hex,"hash":hex}` with
//! `hash = SHA-256(prev_hash_bytes || canonical_json({seq,ts,kind,data}))`. Any edit, deletion,
//! insertion or reordering breaks the chain at that line.

use std::io::{BufRead, Write};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const GENESIS: [u8; 32] = [0; 32];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Record {
    pub seq: u64,
    pub ts: u64,
    pub kind: String,
    pub data: Value,
    pub prev: String,
    pub hash: String,
}

#[derive(Serialize)]
struct Body<'a> {
    seq: u64,
    ts: u64,
    kind: &'a str,
    data: &'a Value,
}

fn digest(prev: &[u8; 32], seq: u64, ts: u64, kind: &str, data: &Value) -> [u8; 32] {
    let body = serde_json::to_vec(&Body { seq, ts, kind, data }).expect("serialisable");
    let mut h = Sha256::new();
    h.update(prev);
    h.update(&body);
    h.finalize().into()
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuditError {
    #[error("line {line}: malformed record: {msg}")]
    Malformed { line: usize, msg: String },
    #[error("line {line}: sequence {got} (expected {want}) — record missing, inserted or reordered")]
    Sequence { line: usize, got: u64, want: u64 },
    #[error("line {line}: chain broken — record modified or reordered")]
    Chain { line: usize },
    #[error("io: {0}")]
    Io(String),
}

/// Writer state: the hash and sequence of the last record.
#[derive(Debug, Clone)]
pub struct Chain {
    pub last: [u8; 32],
    pub next_seq: u64,
}

impl Default for Chain {
    fn default() -> Self {
        Self { last: GENESIS, next_seq: 0 }
    }
}

impl Chain {
    /// Resume from an existing log (verifying it fully).
    pub fn resume<R: BufRead>(r: R) -> Result<Self, AuditError> {
        verify(r)
    }

    /// Build the next record and advance the chain.
    pub fn append(&mut self, ts: u64, kind: &str, data: Value) -> Record {
        let h = digest(&self.last, self.next_seq, ts, kind, &data);
        let rec = Record {
            seq: self.next_seq,
            ts,
            kind: kind.to_owned(),
            data,
            prev: hex::encode(self.last),
            hash: hex::encode(h),
        };
        self.last = h;
        self.next_seq += 1;
        rec
    }

    pub fn write<W: Write>(&mut self, w: &mut W, ts: u64, kind: &str, data: Value) -> std::io::Result<Record> {
        let rec = self.append(ts, kind, data);
        let mut line = serde_json::to_vec(&rec).expect("serialisable");
        line.push(b'\n');
        w.write_all(&line)?;
        w.flush()?;
        Ok(rec)
    }
}

/// Verify a whole log; returns the chain state after the last record.
pub fn verify<R: BufRead>(r: R) -> Result<Chain, AuditError> {
    let mut chain = Chain::default();
    for (i, line) in r.lines().enumerate() {
        let line_no = i + 1;
        let line = line.map_err(|e| AuditError::Io(e.to_string()))?;
        if line.trim().is_empty() {
            continue;
        }
        let rec: Record = serde_json::from_str(&line)
            .map_err(|e| AuditError::Malformed { line: line_no, msg: e.to_string() })?;
        if rec.seq != chain.next_seq {
            return Err(AuditError::Sequence { line: line_no, got: rec.seq, want: chain.next_seq });
        }
        if rec.prev != hex::encode(chain.last) {
            return Err(AuditError::Chain { line: line_no });
        }
        let h = digest(&chain.last, rec.seq, rec.ts, &rec.kind, &rec.data);
        if rec.hash != hex::encode(h) {
            return Err(AuditError::Chain { line: line_no });
        }
        chain.last = h;
        chain.next_seq += 1;
    }
    Ok(chain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn log(n: u64) -> Vec<u8> {
        let mut c = Chain::default();
        let mut out = Vec::new();
        for i in 0..n {
            c.write(&mut out, 1000 + i, "apply", json!({"serial": i})).unwrap();
        }
        out
    }

    #[test]
    fn valid_chain_verifies_and_resumes() {
        let l = log(5);
        let c = verify(&l[..]).unwrap();
        assert_eq!(c.next_seq, 5);
        let mut c2 = Chain::resume(&l[..]).unwrap();
        let mut more = l.clone();
        c2.write(&mut more, 2000, "block", json!({})).unwrap();
        assert_eq!(verify(&more[..]).unwrap().next_seq, 6);
    }

    #[test]
    fn detects_modification_deletion_reordering() {
        let l = String::from_utf8(log(4)).unwrap();
        let lines: Vec<&str> = l.lines().collect();

        let modified = l.replace("\"serial\":2", "\"serial\":9");
        assert!(matches!(verify(modified.as_bytes()), Err(AuditError::Chain { line: 3 })));

        let deleted = [lines[0], lines[2], lines[3]].join("\n");
        assert!(matches!(verify(deleted.as_bytes()), Err(AuditError::Sequence { line: 2, .. })));

        let swapped = [lines[0], lines[2], lines[1], lines[3]].join("\n");
        assert!(verify(swapped.as_bytes()).is_err());
    }
}
