//! Sparse tape index: equality with the TypeScript algorithm, bounds, staleness and errors.
use std::io::Cursor;
use tl_collator_service::tape::{TapeEntry, TapeError};
use tl_collator_service::tapeindex::*;

fn line(seq: u64) -> String {
    format!(
        "{{\"v\":1,\"seq\":{seq},\"pad\":\"{}\"}}\n",
        "x".repeat((seq % 7) as usize)
    )
}

fn tape(n: u64) -> Vec<u8> {
    (1..=n).flat_map(|s| line(s).into_bytes()).collect()
}

/// `buildIndex` second ("accurate") pass of src/tapeIndex.ts, byte for byte.
fn ts_offsets(bytes: &[u8], stride: u64) -> Vec<u64> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut seq = 0u64;
    while pos < bytes.len() {
        let nl = bytes[pos..].iter().position(|b| *b == b'\n');
        let end = nl.map_or(bytes.len(), |i| pos + i);
        let raw = std::str::from_utf8(&bytes[pos..end]).unwrap().trim();
        let this = pos as u64;
        pos = nl.map_or(bytes.len(), |i| pos + i + 1);
        if raw.is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(raw).unwrap();
        if let Some(s) = v["seq"].as_u64() {
            seq = s;
        }
        if seq == 1 || (seq - 1).is_multiple_of(stride) {
            out.push(this);
        }
    }
    out
}

/// `findStartOffset` of src/tapeIndex.ts.
fn ts_find(offsets: &[u64], stride: u64, from: u64) -> u64 {
    if from <= 1 {
        return 0;
    }
    let block = ((from - 1) / stride) as usize;
    offsets.get(block).copied().unwrap_or(0)
}

fn offset_of_seq(bytes: &[u8], seq: u64) -> u64 {
    (1..seq)
        .map(|s| line(s).len() as u64)
        .sum::<u64>()
        .min(bytes.len() as u64)
}

fn reference(bytes: &[u8], from: u64, max: usize) -> Vec<TapeEntry> {
    String::from_utf8(bytes.to_vec())
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| TapeEntry {
            seq: serde_json::from_str::<serde_json::Value>(l).unwrap()["seq"]
                .as_u64()
                .unwrap(),
            line: l.trim().to_owned(),
        })
        .filter(|e| e.seq >= from)
        .take(max)
        .collect()
}

#[test]
fn offsets_and_lookups_equal_the_typescript_for_every_in_range_target() {
    for stride in [1u64, 2, 3, 7, 10, 1000] {
        let bytes = tape(53);
        let idx = TapeIndex::build(&bytes, stride, 1 << 20).unwrap();
        let ts = ts_offsets(&bytes, stride);
        let ours: Vec<u64> = idx.entries().iter().map(|e| e.offset).collect();
        assert_eq!(ours, ts, "stride {stride}");
        assert_eq!(idx.tape_size(), bytes.len() as u64);
        assert!(idx.is_fresh(bytes.len() as u64));
        assert!(!idx.is_fresh(bytes.len() as u64 + 1));
        assert_eq!(idx.last_seq(), Some(53));
        for from in 0..=53u64 {
            let got = idx.find_start(from);
            assert_eq!(
                got.offset,
                ts_find(&ts, stride, from),
                "stride {stride} from {from}"
            );
            // The returned entry really is the line with that seq.
            assert_eq!(got.offset, offset_of_seq(&bytes, got.seq));
        }
        // Beyond the tape the TS falls back to offset 0 (a full scan); ours starts at the last
        // indexed entry. Both yield no entries because nothing has seq >= from.
        for from in 54..=2100u64 {
            let got = idx.find_start(from);
            assert!(got.seq <= 53);
            let legacy = ts_find(&ts, stride, from);
            assert!(legacy == 0 || legacy == got.offset);
            let r = read_range_at(&mut Cursor::new(&bytes), Some(&idx), from, 10).unwrap();
            assert!(r.entries.is_empty());
        }
    }
}

#[test]
fn lookup_is_the_greatest_indexed_seq_at_or_before_and_never_beyond() {
    let bytes = tape(100);
    let idx = TapeIndex::build(&bytes, 7, 1 << 20).unwrap();
    for from in 0..=130u64 {
        let got = idx.find_start(from);
        assert!(got.seq <= from.max(1));
        let best = idx
            .entries()
            .iter()
            .filter(|e| e.seq <= from.max(1))
            .map(|e| e.seq)
            .max()
            .unwrap();
        assert_eq!(got.seq, best);
    }
    // Sparse: seq 1, 8, 15, ...
    let seqs: Vec<u64> = idx.entries().iter().map(|e| e.seq).collect();
    assert_eq!(&seqs[..4], &[1, 8, 15, 22]);
    assert_eq!(idx.find_start(14).seq, 8);
    assert_eq!(idx.find_start(15).seq, 15);
    assert_eq!(idx.find_start(1).seq, 1);
    assert_eq!(idx.find_start(0).offset, 0);
}

#[test]
fn indexed_reads_return_exactly_the_unindexed_entries() {
    let bytes = tape(60);
    for stride in [1u64, 4, 25] {
        let idx = TapeIndex::build(&bytes, stride, 1 << 20).unwrap();
        for from in [0u64, 1, 2, 4, 5, 24, 25, 26, 59, 60, 61] {
            for max in [0usize, 1, 3, 100] {
                let want = reference(&bytes, from, max);
                let got = read_range_at(&mut Cursor::new(&bytes), Some(&idx), from, max).unwrap();
                assert_eq!(got.entries, want, "stride {stride} from {from} max {max}");
                if max > 0 && from > 1 && (from - 1) >= stride && from <= 60 {
                    assert!(got.used_index && !got.index_rejected);
                }
                let plain = read_range_at(&mut Cursor::new(&bytes), None, from, max).unwrap();
                assert_eq!(plain.entries, want);
                assert!(!plain.used_index);
            }
        }
    }
}

#[test]
fn contiguous_batches_walk_the_whole_tape() {
    let bytes = tape(37);
    let idx = TapeIndex::build(&bytes, 5, 1 << 20).unwrap();
    let mut from = 1;
    let mut all = Vec::new();
    loop {
        let r = read_range_at(&mut Cursor::new(&bytes), Some(&idx), from, 4).unwrap();
        if r.entries.is_empty() {
            break;
        }
        from = r.entries.last().unwrap().seq + 1;
        all.extend(r.entries);
    }
    assert_eq!(
        all.iter().map(|e| e.seq).collect::<Vec<_>>(),
        (1..=37).collect::<Vec<_>>()
    );
}

#[test]
fn memory_is_bounded_by_halving_the_stride() {
    let bytes = tape(200);
    let idx = TapeIndex::build(&bytes, 3, 8).unwrap();
    assert!(idx.len() <= 8);
    assert!(
        idx.stride() >= 3 && idx.stride().is_multiple_of(3) && (idx.stride() / 3).is_power_of_two()
    );
    assert_eq!(idx.base_stride(), 3);
    for (i, e) in idx.entries().iter().enumerate() {
        assert_eq!(e.seq, i as u64 * idx.stride() + 1, "plain stride-s index");
        assert_eq!(e.offset, offset_of_seq(&bytes, e.seq));
    }
    // It is exactly the index a fresh build with that stride would give.
    let plain = TapeIndex::build(&bytes, idx.stride(), 1 << 20).unwrap();
    assert_eq!(plain.entries(), idx.entries());
    for from in 0..=210u64 {
        let want = reference(&bytes, from, 5);
        let got = read_range_at(&mut Cursor::new(&bytes), Some(&idx), from, 5).unwrap();
        assert_eq!(got.entries, want, "from {from}");
        assert!(idx.find_start(from).seq <= from.max(1));
    }
}

#[test]
fn record_append_equals_a_rebuild_including_across_halvings() {
    for (stride, cap) in [(1u64, 1usize << 20), (4, 1 << 20), (3, 4), (1, 2)] {
        let mut idx = TapeIndex::empty(stride, cap).unwrap();
        let mut bytes = Vec::new();
        for seq in 1..=90u64 {
            let l = line(seq);
            idx.record_append(seq, l.len() as u64).unwrap();
            bytes.extend_from_slice(l.as_bytes());
            let rebuilt = TapeIndex::build(&bytes, stride, cap).unwrap();
            assert_eq!(idx, rebuilt, "stride {stride} cap {cap} seq {seq}");
        }
    }
    // A non-continuation (skipped or repeated seq) is refused, the index is unchanged.
    let mut idx = TapeIndex::build(&tape(3), 2, 16).unwrap();
    let before = idx.clone();
    assert!(matches!(
        idx.record_append(5, 10),
        Err(IndexError::NotContiguous {
            expected: 4,
            found: 5
        })
    ));
    assert!(matches!(
        idx.record_append(3, 10),
        Err(IndexError::NotContiguous { .. })
    ));
    assert_eq!(idx, before);
}

#[test]
fn build_rejects_what_the_legacy_builder_silently_skipped() {
    // Legacy: a line without `seq` re-used the previous seq and pushed a duplicate offset
    // at a stride boundary, shifting every later block. Here the build fails instead.
    let mut b = tape(2);
    b.extend_from_slice(b"{\"v\":1,\"nope\":true}\n");
    assert_eq!(TapeIndex::build(&b, 1, 16), Err(IndexError::BadLine));
    let mut b = tape(2);
    b.extend_from_slice(b"{\"seq\":\"3\"}\n");
    assert_eq!(TapeIndex::build(&b, 1, 16), Err(IndexError::BadLine));
    let mut b = tape(2);
    b.extend_from_slice(b"not json\n");
    assert_eq!(TapeIndex::build(&b, 1, 16), Err(IndexError::BadLine));
    // gap, repeat, regression, not starting at 1
    let mut b = tape(2);
    b.extend_from_slice(line(4).as_bytes());
    assert_eq!(
        TapeIndex::build(&b, 1, 16),
        Err(IndexError::NotContiguous {
            expected: 3,
            found: 4
        })
    );
    let mut b = tape(2);
    b.extend_from_slice(line(2).as_bytes());
    assert!(matches!(
        TapeIndex::build(&b, 1, 16),
        Err(IndexError::NotContiguous { .. })
    ));
    assert!(matches!(
        TapeIndex::build(line(2).as_bytes(), 1, 16),
        Err(IndexError::NotContiguous {
            expected: 1,
            found: 2
        })
    ));
    // parameters
    assert_eq!(TapeIndex::build(b"", 0, 16), Err(IndexError::BadStride));
    assert_eq!(
        TapeIndex::build(b"", MAX_STRIDE + 1, 16),
        Err(IndexError::BadStride)
    );
    assert_eq!(TapeIndex::build(b"", 1, 1), Err(IndexError::BadCapacity));
    assert_eq!(
        TapeIndex::build(b"", 1, MAX_ENTRIES + 1),
        Err(IndexError::BadCapacity)
    );
    // an enormous line
    let mut big = b"{\"seq\":1,\"pad\":\"".to_vec();
    big.extend(std::iter::repeat_n(b'x', 1_100_000));
    big.extend_from_slice(b"\"}\n");
    assert_eq!(TapeIndex::build(&big, 1, 16), Err(IndexError::TooLarge));
}

#[test]
fn blank_lines_crlf_and_a_torn_tail_are_handled_like_the_legacy_offsets() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"\n");
    bytes.extend_from_slice(line(1).trim_end().as_bytes());
    bytes.extend_from_slice(b"\r\n");
    bytes.extend_from_slice(b"  \n");
    bytes.extend_from_slice(line(2).as_bytes());
    bytes.extend_from_slice(line(3).as_bytes());
    let committed = bytes.len() as u64;
    bytes.extend_from_slice(b"{\"seq\":4,\"pa"); // unacknowledged tail
    let idx = TapeIndex::build(&bytes, 2, 16).unwrap();
    assert_eq!(idx.last_seq(), Some(3));
    assert_eq!(idx.tape_size(), committed, "the torn tail is not covered");
    assert!(!idx.is_fresh(bytes.len() as u64));
    let seqs: Vec<(u64, u64)> = idx.entries().iter().map(|e| (e.seq, e.offset)).collect();
    let third = committed - line(3).len() as u64;
    assert_eq!(seqs, vec![(1, 1), (3, third)]);
    let r = read_range_at(&mut Cursor::new(&bytes), None, 1, 10).unwrap();
    assert_eq!(
        r.entries.iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert!(!r.entries[0].line.ends_with('\r'));
}

#[test]
fn a_stale_or_lying_index_costs_a_scan_never_a_wrong_answer() {
    let bytes = tape(40);
    let idx = TapeIndex::build(&bytes, 5, 1 << 20).unwrap();
    let want = reference(&bytes, 22, 6);

    // Longer file than the index knows: not fresh, scan from the start.
    let mut longer = bytes.clone();
    longer.extend_from_slice(line(41).as_bytes());
    let r = read_range_at(&mut Cursor::new(&longer), Some(&idx), 22, 6).unwrap();
    assert_eq!(r.entries, want);
    assert!(!r.used_index && r.index_rejected);

    // Same length, different content (the legacy size-only test accepts this): replace two
    // lines of equal width so offsets shift, then ask for an entry after the swap.
    let mut swapped = Vec::new();
    let mut lines: Vec<Vec<u8>> = (1..=40).map(|s| line(s).into_bytes()).collect();
    lines.swap(2, 3); // seq 4 now before seq 3 -> not contiguous
    for l in &lines {
        swapped.extend_from_slice(l);
    }
    assert_eq!(swapped.len(), bytes.len());
    // The index still points into the middle; the line found there no longer carries the
    // indexed seq or the scan finds a gap, and the answer is an error, not a silent wrong list.
    let r = read_range_at(&mut Cursor::new(&swapped), Some(&idx), 22, 6);
    match r {
        Ok(r) => assert_eq!(r.entries, reference(&swapped, 22, 6)),
        Err(e) => assert_eq!(e, TapeError::Invalid),
    }

    // Offset pointing at the wrong line of an otherwise intact tape: detected and rescanned.
    let mut forged = TapeIndex::build(&bytes, 5, 1 << 20).unwrap();
    let json = forged.to_legacy_json();
    let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
    v["offsets"][2] = serde_json::json!(offset_of_seq(&bytes, 12)); // seq 11 -> offset of seq 12
    forged = TapeIndex::from_legacy_json(&v.to_string(), 1 << 20).unwrap();
    let r = read_range_at(&mut Cursor::new(&bytes), Some(&forged), 13, 4).unwrap();
    assert_eq!(r.entries, reference(&bytes, 13, 4));
    assert!(r.index_rejected && !r.used_index);
}

#[test]
fn reads_skip_an_unterminated_tail_and_reject_a_noncontiguous_file() {
    let mut bytes = tape(5);
    bytes.extend_from_slice(b"{\"seq\":6");
    let r = read_range_at(&mut Cursor::new(&bytes), None, 1, 100).unwrap();
    assert_eq!(r.entries.len(), 5);

    let mut gap = tape(3);
    gap.extend_from_slice(line(5).as_bytes());
    assert_eq!(
        read_range_at(&mut Cursor::new(&gap), None, 1, 100),
        Err(TapeError::Invalid)
    );
    let empty: Vec<u8> = Vec::new();
    assert!(read_range_at(&mut Cursor::new(&empty), None, 1, 5)
        .unwrap()
        .entries
        .is_empty());
}

#[test]
fn legacy_index_file_round_trips_and_is_validated() {
    let bytes = tape(30);
    let idx = TapeIndex::build(&bytes, 4, 1 << 20).unwrap();
    let text = idx.to_legacy_json();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["stride"], 4);
    assert_eq!(v["tapeSize"], bytes.len());
    let ts: Vec<u64> = v["offsets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o.as_u64().unwrap())
        .collect();
    assert_eq!(ts, ts_offsets(&bytes, 4));

    let loaded = TapeIndex::from_legacy_json(&text, 1 << 20).unwrap();
    assert_eq!(loaded.entries(), idx.entries());
    assert_eq!(loaded.last_seq(), None);
    for from in 0..=30u64 {
        assert_eq!(loaded.find_start(from), idx.find_start(from));
    }
    let r = read_range_at(&mut Cursor::new(&bytes), Some(&loaded), 17, 3).unwrap();
    assert_eq!(r.entries, reference(&bytes, 17, 3));
    assert!(r.used_index);
    // It cannot be extended in place (the file does not record the last seq): rebuild.
    let mut loaded = loaded;
    assert_eq!(loaded.record_append(31, 10), Err(IndexError::Stale));

    let size = bytes.len();
    for (bad, why) in [
        ("not json".to_string(), "json"),
        (
            format!(r#"{{"tapeSize":{size},"offsets":[0]}}"#),
            "no stride",
        ),
        (
            format!(r#"{{"stride":0,"tapeSize":{size},"offsets":[0]}}"#),
            "stride 0",
        ),
        (
            format!(r#"{{"stride":-1,"tapeSize":{size},"offsets":[0]}}"#),
            "negative stride",
        ),
        (
            r#"{"stride":4,"tapeSize":"x","offsets":[0]}"#.to_string(),
            "size type",
        ),
        (
            format!(r#"{{"stride":4,"tapeSize":{size},"offsets":"x"}}"#),
            "offsets type",
        ),
        (
            format!(r#"{{"stride":4,"tapeSize":{size},"offsets":[5,9]}}"#),
            "first not 0",
        ),
        (
            format!(r#"{{"stride":4,"tapeSize":{size},"offsets":[0,9,9]}}"#),
            "not increasing",
        ),
        (
            format!(r#"{{"stride":4,"tapeSize":{size},"offsets":[0,"9"]}}"#),
            "string offset",
        ),
        (
            format!(r#"{{"stride":4,"tapeSize":{size},"offsets":[0,-3]}}"#),
            "negative offset",
        ),
        (
            format!(r#"{{"stride":4,"tapeSize":{size},"offsets":[0,1.5]}}"#),
            "float offset",
        ),
        (
            format!(
                r#"{{"stride":4,"tapeSize":{size},"offsets":[0,{}]}}"#,
                size + 5
            ),
            "offset beyond size",
        ),
    ] {
        assert!(TapeIndex::from_legacy_json(&bad, 1 << 20).is_err(), "{why}");
    }
    assert_eq!(
        TapeIndex::from_legacy_json(&text, 3),
        Err(IndexError::TooLarge),
        "more offsets than the memory bound"
    );
}

/// Output of the real legacy `src/tapeIndex.ts` (blob d12b1c53) for the same synthetic tape,
/// produced by `scripts/compare-legacy-tapeindex.mjs` on Node 24 (type stripping).
#[test]
fn matches_the_output_of_the_pinned_legacy_module() {
    let fx: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/tapeindex_legacy.json")).unwrap();
    assert_eq!(fx["blob"], "d12b1c53");
    let lines = fx["lines"].as_u64().unwrap();
    let bytes = tape(lines);
    let mut checked = 0;
    for case in fx["cases"].as_array().unwrap() {
        let stride = case["stride"].as_u64().unwrap();
        let idx = TapeIndex::build(&bytes, stride, 1 << 20).unwrap();
        assert_eq!(case["tapeSize"].as_u64().unwrap(), idx.tape_size());
        assert!(case["fresh"].as_bool().unwrap());
        let offsets: Vec<u64> = case["offsets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o.as_u64().unwrap())
            .collect();
        assert_eq!(
            offsets,
            idx.entries().iter().map(|e| e.offset).collect::<Vec<_>>()
        );
        // The legacy file format is what we write.
        let ours: serde_json::Value = serde_json::from_str(&idx.to_legacy_json()).unwrap();
        assert_eq!(ours["offsets"], case["offsets"]);
        assert_eq!(ours["stride"], case["stride"]);
        assert_eq!(ours["tapeSize"], case["tapeSize"]);
        for f in case["finds"].as_array().unwrap() {
            let from = f[0].as_u64().unwrap();
            let want = f[1].as_u64().unwrap();
            let got = idx.find_start(from).offset;
            if from <= lines {
                assert_eq!(got, want, "stride {stride} from {from}");
            } else {
                // Beyond the tape the legacy restarts at 0; ours is the last indexed entry.
                assert!(want == 0 || want == got);
            }
            checked += 1;
        }
    }
    assert_eq!(checked, 6 * 61);
}
