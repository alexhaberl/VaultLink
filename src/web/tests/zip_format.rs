#[test]
fn public_preview_back_link_returns_share_parent() {
    assert_eq!(public_back_link("/v/tok", "file.txt", false), "/v/tok");
    assert_eq!(public_back_link("/v/tok", "file.txt", true), "/v/tok");
    assert_eq!(
        public_back_link("/v/tok", "folder/file.txt", true),
        "/v/tok?path=folder"
    );
    assert_eq!(
        public_back_link("/api/v2/public/shares/tok", "folder/file.txt", true),
        "/api/v2/public/shares/tok?path=folder"
    );
}

#[test]
fn storage_full_error_maps_linux_quota_and_space_errors() {
    assert!(storage_full_error(&std::io::Error::from_raw_os_error(28)));
    assert!(storage_full_error(&std::io::Error::from_raw_os_error(122)));
    assert!(!storage_full_error(&std::io::Error::from_raw_os_error(13)));
}

fn assert_zip64_local_record(archive: &[u8]) {
    assert_eq!(zip_u32(archive, 0), 0x0403_4b50);
    assert_eq!(zip_u16(archive, 4), ZIP64_VERSION);
    assert_eq!(zip_u16(archive, 6), 0x0808);
    assert_eq!(zip_u32(archive, 18), u32::MAX);
    assert_eq!(zip_u32(archive, 22), u32::MAX);
    assert_eq!(zip_u16(archive, 26), 8);
    assert_eq!(zip_u16(archive, 28), ZIP64_LOCAL_EXTRA_SIZE as u16);
    assert_eq!(&archive[30..38], b"tiny.bin");
    assert_eq!(zip_u16(archive, 38), 0x0001);
    assert_eq!(zip_u16(archive, 40), ZIP64_SIZE_FIELDS_SIZE);
    assert_eq!(zip_u64(archive, 42), 0);
    assert_eq!(zip_u64(archive, 50), 0);
    assert_eq!(&archive[58..61], b"abc");
}

fn assert_zip64_descriptor_and_central_record(archive: &[u8]) {
    assert_eq!(zip_u32(archive, 61), 0x0807_4b50);
    assert_eq!(zip_u32(archive, 65), 0x3524_41c2);
    assert_eq!(zip_u64(archive, 69), 3);
    assert_eq!(zip_u64(archive, 77), 3);
    assert_eq!(zip_u32(archive, 85), 0x0201_4b50);
    assert_eq!(zip_u16(archive, 89), ZIP64_VERSION);
    assert_eq!(zip_u16(archive, 91), ZIP64_VERSION);
    assert_eq!(zip_u32(archive, 105), u32::MAX);
    assert_eq!(zip_u32(archive, 109), u32::MAX);
    assert_eq!(zip_u16(archive, 115), ZIP64_CENTRAL_EXTRA_SIZE as u16);
    assert_eq!(zip_u32(archive, 127), u32::MAX);
    assert_eq!(&archive[131..139], b"tiny.bin");
    assert_eq!(zip_u16(archive, 139), 0x0001);
    assert_eq!(zip_u16(archive, 141), ZIP64_EXTRA_PAYLOAD_SIZE);
    assert_eq!(zip_u64(archive, 143), 3);
    assert_eq!(zip_u64(archive, 151), 3);
    assert_eq!(zip_u64(archive, 159), 0);
}

fn assert_zip64_end_records(archive: &[u8]) {
    assert_eq!(zip_u32(archive, 167), 0x0606_4b50);
    assert_eq!(zip_u64(archive, 171), 44);
    assert_eq!(zip_u16(archive, 179), ZIP64_VERSION);
    assert_eq!(zip_u16(archive, 181), ZIP64_VERSION);
    assert_eq!(zip_u64(archive, 191), 1);
    assert_eq!(zip_u64(archive, 199), 1);
    assert_eq!(zip_u64(archive, 207), 82);
    assert_eq!(zip_u64(archive, 215), 85);
    assert_eq!(zip_u32(archive, 223), 0x0706_4b50);
    assert_eq!(zip_u64(archive, 231), 167);
    assert_eq!(zip_u32(archive, 239), 1);
    assert_eq!(zip_u32(archive, 243), 0x0605_4b50);
    assert_eq!(zip_u16(archive, 251), u16::MAX);
    assert_eq!(zip_u16(archive, 253), u16::MAX);
    assert_eq!(zip_u32(archive, 255), u32::MAX);
    assert_eq!(zip_u32(archive, 259), u32::MAX);
}

fn assert_empty_zip64_archive(archive: &[u8]) {
    assert_eq!(archive.len(), 98);
    assert_eq!(zip_u32(archive, 0), 0x0606_4b50);
    assert_eq!(zip_u64(archive, 24), 0);
    assert_eq!(zip_u32(archive, 56), 0x0706_4b50);
    assert_eq!(zip_u32(archive, 76), 0x0605_4b50);
}

#[test]
fn every_zip_archive_uses_full_zip64_records() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("docs")).unwrap();
    std::fs::write(root.path().join("docs/tiny.bin"), b"abc").unwrap();
    let state = test_state(root.path(), data.path());
    let scope = state.secure_root().bind_directory("docs").unwrap();
    let files = vec![ZipFilePlan {
        source_path: "tiny.bin".into(),
        archive_name: "tiny.bin".into(),
        scanned_len: 3,
        is_directory: false,
    }];
    let plan = ZipPlan {
        estimated_archive_size: estimate_zip_archive_size(&files).unwrap(),
        files,
        max_data_size: 3,
    };

    let archive = write_zip_archive(&scope, &plan, Vec::new()).unwrap();
    assert_eq!(archive.len() as u64, plan.estimated_archive_size);
    assert_eq!(archive.len(), 265);

    assert_zip64_local_record(&archive);
    assert_zip64_descriptor_and_central_record(&archive);
    assert_zip64_end_records(&archive);

    let empty_files = Vec::<ZipFilePlan>::new();
    let empty_plan = ZipPlan {
        estimated_archive_size: estimate_zip_archive_size(&empty_files).unwrap(),
        files: empty_files,
        max_data_size: 0,
    };
    let empty_archive = write_zip_archive(&scope, &empty_plan, Vec::new()).unwrap();
    assert_empty_zip64_archive(&empty_archive);
}

#[test]
fn every_central_entry_uses_zip64_sizes_and_offset() {
    let mut central = Vec::new();
    write_streaming_central_entry(
        &mut central,
        &StreamingZipEntry {
            name: "x",
            crc: 7,
            size: 9,
            local_offset: 11,
            is_directory: false,
        },
    )
    .unwrap();
    assert_eq!(central.len(), 75);
    assert_eq!(zip_u16(&central, 4), ZIP64_VERSION);
    assert_eq!(zip_u32(&central, 20), u32::MAX);
    assert_eq!(zip_u32(&central, 24), u32::MAX);
    assert_eq!(zip_u16(&central, 30), ZIP64_CENTRAL_EXTRA_SIZE as u16);
    assert_eq!(zip_u32(&central, 42), u32::MAX);
    assert_eq!(&central[46..47], b"x");
    assert_eq!(zip_u16(&central, 47), 0x0001);
    assert_eq!(zip_u16(&central, 49), ZIP64_EXTRA_PAYLOAD_SIZE);
    assert_eq!(zip_u64(&central, 51), 9);
    assert_eq!(zip_u64(&central, 59), 9);
    assert_eq!(zip_u64(&central, 67), 11);
}

#[test]
fn zip64_end_records_preserve_64_bit_directory_values() {
    let entries = u16::MAX as u64;
    let central_size = u32::MAX as u64 + 3;
    let central_offset = u32::MAX as u64 + 9;
    let zip64_eocd_offset = 0x2_0000_0042;
    let mut records = Vec::new();
    write_streaming_zip64_eocd(&mut records, entries, central_size, central_offset).unwrap();
    write_streaming_zip64_locator(&mut records, zip64_eocd_offset).unwrap();
    write_streaming_eocd(&mut records).unwrap();

    assert_eq!(records.len(), 98);
    assert_eq!(zip_u32(&records, 0), 0x0606_4b50);
    assert_eq!(zip_u64(&records, 4), 44);
    assert_eq!(zip_u16(&records, 12), ZIP64_VERSION);
    assert_eq!(zip_u16(&records, 14), ZIP64_VERSION);
    assert_eq!(zip_u64(&records, 24), entries);
    assert_eq!(zip_u64(&records, 32), entries);
    assert_eq!(zip_u64(&records, 40), central_size);
    assert_eq!(zip_u64(&records, 48), central_offset);
    assert_eq!(zip_u32(&records, 56), 0x0706_4b50);
    assert_eq!(zip_u64(&records, 64), zip64_eocd_offset);
    assert_eq!(zip_u32(&records, 72), 1);
    assert_eq!(zip_u32(&records, 76), 0x0605_4b50);
    assert_eq!(zip_u16(&records, 84), u16::MAX);
    assert_eq!(zip_u16(&records, 86), u16::MAX);
    assert_eq!(zip_u32(&records, 88), u32::MAX);
    assert_eq!(zip_u32(&records, 92), u32::MAX);
}

#[test]
fn always_zip64_estimate_is_fixed_and_rejects_u64_overflow() {
    assert_eq!(estimate_zip_archive_size(&[]).unwrap(), 98);

    let tiny_file = ZipFilePlan {
        source_path: "tiny.bin".into(),
        archive_name: "tiny.bin".into(),
        scanned_len: 3,
        is_directory: false,
    };
    assert_eq!(estimate_zip_archive_size(&[tiny_file]).unwrap(), 265);

    let multiple_files = [
        ZipFilePlan {
            source_path: "first".into(),
            archive_name: "x".into(),
            scanned_len: 0,
            is_directory: false,
        },
        ZipFilePlan {
            source_path: "second".into(),
            archive_name: "long".into(),
            scanned_len: 10,
            is_directory: false,
        },
    ];
    assert_eq!(estimate_zip_archive_size(&multiple_files).unwrap(), 414);

    let overflowing_file = ZipFilePlan {
        source_path: "overflow.bin".into(),
        archive_name: "overflow.bin".into(),
        scanned_len: u64::MAX,
        is_directory: false,
    };
    assert!(matches!(
        estimate_zip_archive_size(&[overflowing_file]),
        Err(ZipBuildError::Limit("zip archive size overflow"))
    ));
}

#[test]
fn zip_plan_large_thresholds_switch_to_direct_streaming() {
    assert!(!zip_requires_direct_stream(64 * 1024 * 1024 - 1, 999));
    assert!(zip_requires_direct_stream(64 * 1024 * 1024, 999));
    assert!(zip_requires_direct_stream(0, 1_000));
}

#[test]
fn zip_plan_memory_is_bounded_at_sixteen_mibibytes() {
    let initial = std::mem::size_of::<ZipPlan>();
    let available_path_bytes = ZIP_PLAN_MAX_BYTES
        .checked_sub(initial + std::mem::size_of::<ZipFilePlan>())
        .unwrap();
    assert_eq!(
        checked_zip_plan_memory(initial, available_path_bytes, 0).unwrap(),
        ZIP_PLAN_MAX_BYTES
    );
    assert!(matches!(
        checked_zip_plan_memory(initial, available_path_bytes + 1, 0),
        Err(ZipBuildError::Limit("zip plan memory limit exceeded"))
    ));
}
