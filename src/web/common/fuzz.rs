//! Bounded, deterministic checks against the production cursor and page code.

use super::*;

const MAX_INPUT_BYTES: usize = 8 * 1024;
const MAX_ENTRIES: usize = 257;

/// The first byte chooses sorting; bytes 1..3 choose 0..257 entries. Remaining
/// bytes supply names, sizes and nanosecond timestamps. The complete input also
/// reaches the untrusted Base64/JSON decoder without requiring valid framing.
pub fn check_directory_cursor(input: &[u8]) {
    let input = &input[..input.len().min(MAX_INPUT_BYTES)];
    let control = |index| input.get(index).copied().unwrap_or(0);
    let column = match control(0) % 4 {
        0 => FileSortColumn::Name,
        1 => FileSortColumn::Type,
        2 => FileSortColumn::Size,
        _ => FileSortColumn::Modified,
    };
    let direction = if control(0) & 4 == 0 {
        FileSortDirection::Ascending
    } else {
        FileSortDirection::Descending
    };
    check_cursor_decoding(input, column, direction);

    let count = usize::from(u16::from_le_bytes([control(1), control(2)])) % (MAX_ENTRIES + 1);
    let entries = (0..count)
        .map(|index| generated_entry(input, index))
        .collect::<Vec<_>>();
    let mut reference = entries.iter().map(clone_entry).collect::<Vec<_>>();
    reference.sort_by(|left, right| reference_order(left, right, column, direction));

    let mut builder = DirectorySnapshotBuilder::new();
    for entry in &entries {
        let encoded = encode_directory_cursor(entry, column, direction).unwrap();
        let decoded = decode_directory_cursor(&encoded, column, direction).unwrap();
        assert_eq!(identity(entry), identity(&decoded));
        builder
            .push(clone_entry(entry), entry_sort_key(entry, column))
            .expect("the bounded fixture fits in one snapshot");
    }
    let mut snapshot = builder.finish(control(0) & 8 != 0);
    snapshot
        .entries
        .sort_by(|left, right| directed_key_order(&left.sort_key, &right.sort_key, direction));
    assert_eq!(
        snapshot
            .entries
            .iter()
            .map(|item| identity(&item.entry))
            .collect::<Vec<_>>(),
        reference.iter().map(identity).collect::<Vec<_>>()
    );
    check_heap(&entries, &reference, column, direction);
    check_pages(&snapshot, &reference, column, direction);
}

fn generated_entry(input: &[u8], index: usize) -> Entry {
    let payload = input.get(3..).unwrap_or_default();
    // Adjacent A/a names deliberately share a folded name and primary values.
    // Pair suffixes keep every real directory name unique.
    let mut bytes = [0; 24];
    if !payload.is_empty() {
        for (offset, byte) in bytes.iter_mut().enumerate() {
            *byte = payload[((index / 2) * 24 + offset) % payload.len()];
        }
    }
    let name = format!(
        "{}{}-{:03}",
        if index.is_multiple_of(2) { 'A' } else { 'a' },
        String::from_utf8_lossy(&bytes[..8]),
        index / 2
    );
    let nanos = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    Entry {
        name,
        is_dir: bytes[0] & 1 != 0,
        len: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        modified: (bytes[0] & 2 != 0).then(|| UNIX_EPOCH + std::time::Duration::from_nanos(nanos)),
    }
}

fn identity(entry: &Entry) -> (&str, bool, u64, Option<std::time::SystemTime>) {
    (&entry.name, entry.is_dir, entry.len, entry.modified)
}

// Intentionally independent of DirectoryEntrySortKey, partition_point and the
// production heap comparator: this is a complete reference sort of small data.
fn reference_order(
    left: &Entry,
    right: &Entry,
    column: FileSortColumn,
    direction: FileSortDirection,
) -> Ordering {
    let primary = match column {
        FileSortColumn::Name => Ordering::Equal,
        FileSortColumn::Type => right.is_dir.cmp(&left.is_dir),
        FileSortColumn::Size => left.len.cmp(&right.len),
        FileSortColumn::Modified => left.modified.cmp(&right.modified),
    };
    let order = primary
        .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
        .then_with(|| left.name.cmp(&right.name));
    if direction == FileSortDirection::Descending {
        order.reverse()
    } else {
        order
    }
}

fn check_cursor_decoding(input: &[u8], column: FileSortColumn, direction: FileSortDirection) {
    let raw = String::from_utf8_lossy(input);
    if let Ok(decoded) = decode_directory_cursor(&raw, column, direction) {
        let canonical = encode_directory_cursor(&decoded, column, direction).unwrap();
        let roundtrip = decode_directory_cursor(&canonical, column, direction).unwrap();
        assert_eq!(identity(&decoded), identity(&roundtrip));
    }
    // Valid JSON framing lets arbitrary values reach field validation even when
    // mutating raw Base64 would otherwise spend most iterations in its decoder.
    let mut value =
        DirectoryCursor::from_entry(&generated_entry(input, 0), column, direction).unwrap();
    value.version = input.first().copied().unwrap_or(0);
    let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).unwrap());
    assert_eq!(
        decode_directory_cursor(&encoded, column, direction).is_ok(),
        value.version == 1
    );
    value.version = 1;
    let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).unwrap());
    let other_direction = if direction == FileSortDirection::Ascending {
        FileSortDirection::Descending
    } else {
        FileSortDirection::Ascending
    };
    assert!(decode_directory_cursor(&encoded, column, other_direction).is_err());
    assert!(decode_directory_cursor(&(encoded + "="), column, direction).is_err());
    assert!(decode_directory_cursor(
        &"x".repeat(DIRECTORY_CURSOR_MAX_BYTES + 1),
        column,
        direction
    )
    .is_err());
}

fn check_heap(
    entries: &[Entry],
    reference: &[Entry],
    column: FileSortColumn,
    direction: FileSortDirection,
) {
    for backwards in [false, true] {
        let mut heap = BinaryHeap::new();
        for entry in entries.iter().rev() {
            retain_ranked_entry(
                &mut heap,
                clone_entry(entry),
                entry_sort_key(entry, column),
                direction,
                backwards,
            );
            assert!(heap.len() <= DIRECTORY_PAGE_SIZE + 1);
        }
        let mut actual = heap.into_iter().map(|item| item.entry).collect::<Vec<_>>();
        actual.sort_by(|left, right| reference_order(left, right, column, direction));
        let retained = reference.len().min(DIRECTORY_PAGE_SIZE + 1);
        let expected = if backwards {
            &reference[reference.len() - retained..]
        } else {
            &reference[..retained]
        };
        assert_eq!(
            actual.iter().map(identity).collect::<Vec<_>>(),
            expected.iter().map(identity).collect::<Vec<_>>()
        );
    }
}

fn check_pages(
    snapshot: &DirectorySnapshot,
    reference: &[Entry],
    column: FileSortColumn,
    direction: FileSortDirection,
) {
    let mut after = None;
    let mut start = 0;
    // A strict bound catches cursor cycles as an assertion instead of a timeout.
    for _ in 0..=MAX_ENTRIES / DIRECTORY_PAGE_SIZE {
        let page = list_directory_snapshot_cursor_page(
            snapshot,
            after.as_deref(),
            None,
            column,
            direction,
        )
        .unwrap();
        let end = (start + DIRECTORY_PAGE_SIZE).min(reference.len());
        assert_eq!(
            page.entries.iter().map(identity).collect::<Vec<_>>(),
            reference[start..end]
                .iter()
                .map(identity)
                .collect::<Vec<_>>()
        );
        assert_eq!(page.truncated, snapshot.truncated);
        assert_eq!(page.next_cursor.is_some(), end < reference.len());
        assert_eq!(page.previous_cursor.is_some(), start != 0);
        if let Some(before) = page.previous_cursor.as_deref() {
            let previous = list_directory_snapshot_cursor_page(
                snapshot,
                None,
                Some(before),
                column,
                direction,
            )
            .unwrap();
            assert_eq!(
                previous.entries.iter().map(identity).collect::<Vec<_>>(),
                reference[start.saturating_sub(DIRECTORY_PAGE_SIZE)..start]
                    .iter()
                    .map(identity)
                    .collect::<Vec<_>>()
            );
            assert!(list_directory_snapshot_cursor_page(
                snapshot,
                Some(before),
                Some(before),
                column,
                direction
            )
            .is_err());
        }
        start = end;
        after = page.next_cursor;
        if after.is_none() {
            assert_eq!(start, reference.len());
            return;
        }
    }
    panic!("pagination exceeded the bounded fixture");
}

#[cfg(test)]
mod tests {
    #[test]
    fn curated_cursor_seeds() {
        for seed in [
            include_bytes!("../../../fuzz/corpus/directory_cursor/empty").as_slice(),
            include_bytes!("../../../fuzz/corpus/directory_cursor/page_100"),
            include_bytes!("../../../fuzz/corpus/directory_cursor/page_101"),
            include_bytes!("../../../fuzz/corpus/directory_cursor/bidirectional_unicode"),
            include_bytes!("../../../fuzz/corpus/directory_cursor/timestamp_max"),
            include_bytes!("../../../fuzz/corpus/directory_cursor/valid_wire_cursor"),
            include_bytes!("../../../fuzz/corpus/directory_cursor/oversized_cursor"),
        ] {
            super::check_directory_cursor(seed);
        }
    }
}
