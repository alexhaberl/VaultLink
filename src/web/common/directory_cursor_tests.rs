#[cfg(test)]
mod directory_cursor_tests {
    use super::*;

    fn entry(index: usize) -> Entry {
        Entry {
            name: format!("entry-{index:05}.txt"),
            is_dir: index.is_multiple_of(7),
            len: (50_000 - index) as u64,
            modified: Some(UNIX_EPOCH + std::time::Duration::from_secs((index % 997) as u64)),
        }
    }

    fn identity(entry: &Entry) -> (&str, bool, u64, Option<std::time::SystemTime>) {
        (&entry.name, entry.is_dir, entry.len, entry.modified)
    }

    #[test]
    fn fifty_thousand_entry_reference_sort_retains_at_most_101_candidates() {
        for column in [
            FileSortColumn::Name,
            FileSortColumn::Type,
            FileSortColumn::Size,
            FileSortColumn::Modified,
        ] {
            for direction in [FileSortDirection::Ascending, FileSortDirection::Descending] {
                let mut expected = (0..50_000).map(entry).collect::<Vec<_>>();
                sort_entries(&mut expected, column, direction);
                for backwards in [false, true] {
                    let mut heap = BinaryHeap::new();
                    for candidate in (0..50_000).map(entry) {
                        let key = entry_sort_key(&candidate, column);
                        retain_ranked_entry(&mut heap, candidate, key, direction, backwards);
                        assert!(heap.len() <= 101);
                    }
                    let mut actual = heap
                        .into_iter()
                        .map(|ranked| ranked.entry)
                        .collect::<Vec<_>>();
                    sort_entries(&mut actual, column, direction);
                    let reference = if backwards {
                        &expected[expected.len() - 101..]
                    } else {
                        &expected[..101]
                    };
                    assert_eq!(
                        actual.iter().map(identity).collect::<Vec<_>>(),
                        reference.iter().map(identity).collect::<Vec<_>>()
                    );
                }
            }
        }
    }

    #[test]
    fn directory_cursor_is_versioned_bounded_and_bound_to_sorting() {
        let boundary = entry(42);
        let cursor = encode_directory_cursor(
            &boundary,
            FileSortColumn::Modified,
            FileSortDirection::Descending,
        )
        .unwrap();
        assert!(cursor.len() <= DIRECTORY_CURSOR_MAX_BYTES);
        let decoded = decode_directory_cursor(
            &cursor,
            FileSortColumn::Modified,
            FileSortDirection::Descending,
        )
        .unwrap();
        assert_eq!(identity(&decoded), identity(&boundary));
        assert!(decode_directory_cursor(
            &cursor,
            FileSortColumn::Name,
            FileSortDirection::Descending
        )
        .is_err());
        assert!(decode_directory_cursor(
            &"x".repeat(DIRECTORY_CURSOR_MAX_BYTES + 1),
            FileSortColumn::Name,
            FileSortDirection::Ascending
        )
        .is_err());
    }

    #[test]
    fn snapshot_cursor_pages_preserve_sort_and_bidirectional_cursor_contract() {
        for column in [
            FileSortColumn::Name,
            FileSortColumn::Type,
            FileSortColumn::Size,
            FileSortColumn::Modified,
        ] {
            for direction in [FileSortDirection::Ascending, FileSortDirection::Descending] {
                let mut expected = (0..1_001).map(entry).collect::<Vec<_>>();
                sort_entries(&mut expected, column, direction);
                let mut builder = DirectorySnapshotBuilder::new();
                for candidate in (0..1_001).rev().map(entry) {
                    let key = entry_sort_key(&candidate, column);
                    builder.push(candidate, key).unwrap();
                }
                let mut snapshot = builder.finish(false);
                snapshot.entries.sort_by(|left, right| {
                    directed_key_order(&left.sort_key, &right.sort_key, direction)
                });

                let first =
                    list_directory_snapshot_cursor_page(&snapshot, None, None, column, direction)
                        .unwrap();
                assert_eq!(first.entries.len(), DIRECTORY_PAGE_SIZE);
                let first_next = first.next_cursor.clone().expect("second page exists");
                let second = list_directory_snapshot_cursor_page(
                    &snapshot,
                    Some(&first_next),
                    None,
                    column,
                    direction,
                )
                .unwrap();
                let second_previous = second
                    .previous_cursor
                    .clone()
                    .expect("second page has a previous cursor");
                let back_to_first = list_directory_snapshot_cursor_page(
                    &snapshot,
                    None,
                    Some(&second_previous),
                    column,
                    direction,
                )
                .unwrap();
                assert_eq!(
                    back_to_first
                        .entries
                        .iter()
                        .map(identity)
                        .collect::<Vec<_>>(),
                    first.entries.iter().map(identity).collect::<Vec<_>>()
                );

                let mut actual = first.entries;
                let mut cursor = Some(first_next);
                while let Some(after) = cursor {
                    let page = list_directory_snapshot_cursor_page(
                        &snapshot,
                        Some(&after),
                        None,
                        column,
                        direction,
                    )
                    .unwrap();
                    cursor = page.next_cursor;
                    actual.extend(page.entries);
                }
                assert_eq!(
                    actual.iter().map(identity).collect::<Vec<_>>(),
                    expected.iter().map(identity).collect::<Vec<_>>()
                );
            }
        }
    }
}
