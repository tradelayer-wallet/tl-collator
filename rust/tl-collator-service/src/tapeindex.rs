//! Sparse tape index (port of `src/tapeIndex.ts` and its use in `src/tape.ts`
//! `replayFromSeq` / `index.ts` TAPE_SUB).
//!
//! Semantics kept from the TypeScript: the index holds the byte offset of the line whose
//! `seq` is `1` or satisfies `(seq - 1) % stride == 0`; a lookup for `fromSeq` returns the
//! offset of the greatest indexed entry at or before it (`findStartOffset`:
//! `offsets[floor((fromSeq - 1) / stride)]`, `0` for `fromSeq <= 1`); freshness compares the
//! recorded size with the tape file size; the legacy `tape.idx` JSON
//! (`{stride, tapeSize, offsets}`) can be loaded and written.
//!
//! Differences (README table): memory is bounded (when `max_entries` is reached the stride
//! doubles and every other entry is dropped, so the index is always the plain stride-`s`
//! index of the tape), the index is extended on append instead of being thrown away and
//! rebuilt by a full scan, a line without a numeric `seq` or a gap in `seq` fails the build
//! instead of silently shifting every later offset, and a lookup is checked against the file
//! (the entry at the returned offset must carry the expected `seq`), because the legacy
//! size-only freshness test accepts a corrupted or swapped index of the same length.
use crate::tape::{TapeEntry, TapeError};
use serde_json::{json, Value};
use std::io::{BufRead, Cursor, Read, Seek, SeekFrom};
use tl_collator_wire::{MAX_INPUT_BYTES, MAX_SAFE_INTEGER};

pub const MAX_STRIDE: u64 = 1 << 32;
pub const MIN_ENTRIES: usize = 2;
pub const MAX_ENTRIES: usize = 1 << 24;
const MAX_LINE: usize = MAX_INPUT_BYTES + 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexError {
    BadStride,
    BadCapacity,
    NotContiguous {
        expected: u64,
        found: u64,
    },
    BadLine,
    TooLarge,
    Io,
    /// Appended entry does not continue the indexed tape.
    Stale,
    BadJson(&'static str),
}

impl std::fmt::Display for IndexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for IndexError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexEntry {
    pub seq: u64,
    pub offset: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TapeIndex {
    /// Current stride; `base_stride * 2^k` after `k` capacity halvings.
    stride: u64,
    base_stride: u64,
    /// Bytes covered (through the last complete line).
    tape_size: u64,
    /// `None` for an index loaded from a legacy file (the file does not say).
    last_seq: Option<u64>,
    /// Invariant: `entries[i].seq == i * stride + 1`.
    entries: Vec<IndexEntry>,
    max_entries: usize,
}

fn check_params(stride: u64, max_entries: usize) -> Result<(), IndexError> {
    if stride == 0 || stride > MAX_STRIDE {
        return Err(IndexError::BadStride);
    }
    if !(MIN_ENTRIES..=MAX_ENTRIES).contains(&max_entries) {
        return Err(IndexError::BadCapacity);
    }
    Ok(())
}

/// Read one line (including its `\n` if present), at most `MAX_LINE` bytes.
/// Returns the number of bytes consumed; 0 at end of input.
fn read_line<R: BufRead>(r: &mut R, buf: &mut Vec<u8>) -> Result<usize, IndexError> {
    buf.clear();
    let mut limited = Read::take(&mut *r, MAX_LINE as u64 + 1);
    let n = limited.read_until(b'\n', buf).map_err(|_| IndexError::Io)?;
    if buf.len() > MAX_LINE {
        return Err(IndexError::TooLarge);
    }
    Ok(n)
}

fn trim(line: &[u8]) -> &[u8] {
    let mut s = 0;
    let mut e = line.len();
    while s < e && line[s].is_ascii_whitespace() {
        s += 1;
    }
    while e > s && line[e - 1].is_ascii_whitespace() {
        e -= 1;
    }
    &line[s..e]
}

fn seq_of(line: &[u8]) -> Result<u64, IndexError> {
    let v: Value = serde_json::from_slice(line).map_err(|_| IndexError::BadLine)?;
    v.get("seq")
        .and_then(Value::as_u64)
        .filter(|s| *s <= MAX_SAFE_INTEGER)
        .ok_or(IndexError::BadLine)
}

impl TapeIndex {
    pub fn empty(stride: u64, max_entries: usize) -> Result<Self, IndexError> {
        check_params(stride, max_entries)?;
        Ok(Self {
            stride,
            base_stride: stride,
            tape_size: 0,
            last_seq: Some(0),
            entries: Vec::new(),
            max_entries,
        })
    }

    /// `buildIndex`: scan the tape once. Only complete (newline-terminated) lines count; an
    /// unterminated tail is not indexed and not covered by `tape_size`.
    pub fn build(bytes: &[u8], stride: u64, max_entries: usize) -> Result<Self, IndexError> {
        Self::build_from_reader(Cursor::new(bytes), stride, max_entries)
    }

    pub fn build_from_reader<R: BufRead>(
        mut reader: R,
        stride: u64,
        max_entries: usize,
    ) -> Result<Self, IndexError> {
        let mut idx = Self::empty(stride, max_entries)?;
        let mut buf = Vec::new();
        let mut pos: u64 = 0;
        loop {
            let n = read_line(&mut reader, &mut buf)?;
            if n == 0 {
                break;
            }
            if buf.last() != Some(&b'\n') {
                break; // torn, unacknowledged tail
            }
            let line = trim(&buf);
            if !line.is_empty() {
                let seq = seq_of(line)?;
                idx.push_line(seq, pos)?;
            }
            pos += n as u64;
            idx.tape_size = pos;
        }
        Ok(idx)
    }

    fn eligible(&self, seq: u64) -> bool {
        seq == 1 || (seq - 1).is_multiple_of(self.stride)
    }

    fn halve(&mut self) -> bool {
        let Some(next) = self.stride.checked_mul(2) else {
            return false;
        };
        self.entries.retain(|e| (e.seq - 1).is_multiple_of(next));
        self.stride = next;
        true
    }

    fn push_line(&mut self, seq: u64, offset: u64) -> Result<(), IndexError> {
        let expected = self.last_seq.ok_or(IndexError::Stale)?.saturating_add(1);
        if seq != expected {
            return Err(IndexError::NotContiguous {
                expected,
                found: seq,
            });
        }
        self.last_seq = Some(seq);
        if self.eligible(seq) {
            if self.entries.len() >= self.max_entries && !self.halve() {
                return Ok(()); // cannot coarsen further: lookups stay correct, only slower
            }
            if self.eligible(seq) {
                self.entries.push(IndexEntry { seq, offset });
            }
        }
        Ok(())
    }

    /// Extend the index for one committed line of `line_len` bytes **including** its `\n`.
    /// The caller appended it at byte `tape_size()`; any other continuation is `Stale`.
    pub fn record_append(&mut self, seq: u64, line_len: u64) -> Result<(), IndexError> {
        let offset = self.tape_size;
        let end = offset.checked_add(line_len).ok_or(IndexError::TooLarge)?;
        self.push_line(seq, offset)?;
        self.tape_size = end;
        Ok(())
    }

    pub fn stride(&self) -> u64 {
        self.stride
    }
    pub fn base_stride(&self) -> u64 {
        self.base_stride
    }
    pub fn tape_size(&self) -> u64 {
        self.tape_size
    }
    pub fn last_seq(&self) -> Option<u64> {
        self.last_seq
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }
    pub fn entries(&self) -> &[IndexEntry] {
        &self.entries
    }

    /// `isIndexFresh`: the recorded size equals the current tape size.
    pub fn is_fresh(&self, tape_len: u64) -> bool {
        self.tape_size == tape_len
    }

    /// `findStartOffset`: the greatest indexed entry with `seq <= from_seq` (never beyond it);
    /// the start of the file (`seq 1`, offset 0) when `from_seq <= 1` or nothing is indexed.
    pub fn find_start(&self, from_seq: u64) -> IndexEntry {
        const START: IndexEntry = IndexEntry { seq: 1, offset: 0 };
        if from_seq <= 1 {
            return START;
        }
        let n = self.entries.partition_point(|e| e.seq <= from_seq);
        if n == 0 {
            START
        } else {
            self.entries[n - 1]
        }
    }

    /// Legacy `tape.idx` content.
    pub fn to_legacy_json(&self) -> String {
        let offsets: Vec<u64> = self.entries.iter().map(|e| e.offset).collect();
        json!({"stride": self.stride, "tapeSize": self.tape_size, "offsets": offsets}).to_string()
    }

    /// `loadIndex`, strictly: integers only (the legacy `Number(n) || 0` turned garbage into
    /// offset 0), offsets strictly increasing from 0, bounded count.
    pub fn from_legacy_json(text: &str, max_entries: usize) -> Result<Self, IndexError> {
        if text.len() > 1 << 28 {
            return Err(IndexError::TooLarge);
        }
        let v: Value = serde_json::from_str(text).map_err(|_| IndexError::BadJson("json"))?;
        let stride = v
            .get("stride")
            .and_then(Value::as_u64)
            .ok_or(IndexError::BadJson("stride"))?;
        check_params(stride, max_entries)?;
        let tape_size = v
            .get("tapeSize")
            .and_then(Value::as_u64)
            .filter(|n| *n <= MAX_SAFE_INTEGER)
            .ok_or(IndexError::BadJson("tapeSize"))?;
        let list = v
            .get("offsets")
            .and_then(Value::as_array)
            .ok_or(IndexError::BadJson("offsets"))?;
        if list.len() > max_entries {
            return Err(IndexError::TooLarge);
        }
        let mut entries = Vec::with_capacity(list.len());
        let mut prev: Option<u64> = None;
        for (i, o) in list.iter().enumerate() {
            let off = o
                .as_u64()
                .filter(|n| *n < tape_size.max(1))
                .ok_or(IndexError::BadJson("offset"))?;
            let ok = match prev {
                None => off == 0,
                Some(p) => off > p,
            };
            if !ok {
                return Err(IndexError::BadJson("offset order"));
            }
            prev = Some(off);
            let seq = (i as u64)
                .checked_mul(stride)
                .and_then(|n| n.checked_add(1))
                .ok_or(IndexError::BadJson("seq"))?;
            entries.push(IndexEntry { seq, offset: off });
        }
        Ok(Self {
            stride,
            base_stride: stride,
            tape_size,
            last_seq: None,
            entries,
            max_entries,
        })
    }
}

/// Result of an indexed range read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeRead {
    pub entries: Vec<TapeEntry>,
    /// A fresh index chose the starting offset.
    pub used_index: bool,
    /// The index disagreed with the file (size or entry at the offset) and a scan from the
    /// start of the file was used instead.
    pub index_rejected: bool,
}

enum Scan {
    Done(Vec<TapeEntry>),
    /// The first line at the indexed offset did not carry the expected `seq`.
    Mismatch,
}

fn scan<R: Read + Seek>(
    reader: &mut R,
    start: IndexEntry,
    from_seq: u64,
    max: usize,
) -> Result<Scan, TapeError> {
    reader
        .seek(SeekFrom::Start(start.offset))
        .map_err(|_| TapeError::Io)?;
    let mut buffered = std::io::BufReader::new(reader);
    let mut out: Vec<TapeEntry> = Vec::new();
    let mut buf = Vec::new();
    let mut first = true;
    let mut prev: Option<u64> = None;
    loop {
        let n = read_line(&mut buffered, &mut buf).map_err(|e| match e {
            IndexError::Io => TapeError::Io,
            _ => TapeError::Invalid,
        })?;
        if n == 0 || buf.last() != Some(&b'\n') {
            break; // end, or an unacknowledged tail
        }
        let line = trim(&buf);
        if line.is_empty() {
            continue;
        }
        let seq = seq_of(line).map_err(|_| TapeError::Invalid)?;
        if first {
            first = false;
            if start.offset > 0 && seq != start.seq {
                return Ok(Scan::Mismatch);
            }
        }
        if prev.is_some_and(|p| seq != p.saturating_add(1)) {
            return Err(TapeError::Invalid);
        }
        prev = Some(seq);
        if seq < from_seq {
            continue;
        }
        let text = String::from_utf8(line.to_vec()).map_err(|_| TapeError::Invalid)?;
        out.push(TapeEntry { seq, line: text });
        if out.len() >= max {
            break;
        }
    }
    Ok(Scan::Done(out))
}

/// `replayFromSeq` for one batch: entries with `seq >= from_seq`, ascending, contiguous, at
/// most `max`. The index only chooses where reading starts; a missing, stale or lying index
/// costs a scan from the start of the file, never a wrong answer.
pub fn read_range_at<R: Read + Seek>(
    reader: &mut R,
    index: Option<&TapeIndex>,
    from_seq: u64,
    max: usize,
) -> Result<RangeRead, TapeError> {
    let len = reader.seek(SeekFrom::End(0)).map_err(|_| TapeError::Io)?;
    let from_seq = from_seq.max(1);
    let (start, used) = match index {
        Some(i) if i.is_fresh(len) => (i.find_start(from_seq), true),
        _ => (IndexEntry { seq: 1, offset: 0 }, false),
    };
    let mut rejected = index.is_some() && !used;
    if max == 0 {
        return Ok(RangeRead {
            entries: Vec::new(),
            used_index: used,
            index_rejected: rejected,
        });
    }
    let entries = match scan(reader, start, from_seq, max)? {
        Scan::Done(v) => v,
        Scan::Mismatch => {
            rejected = true;
            match scan(reader, IndexEntry { seq: 1, offset: 0 }, from_seq, max)? {
                Scan::Done(v) => v,
                Scan::Mismatch => return Err(TapeError::Invalid),
            }
        }
    };
    Ok(RangeRead {
        entries,
        used_index: used && !rejected,
        index_rejected: rejected,
    })
}
