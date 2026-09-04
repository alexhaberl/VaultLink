#[cfg(test)]
mod tests {
    use super::*;

    fn storage() -> Storage {
        Storage {
            root_mount_path: "/mnt/vault link".into(),
            data_directory: "/var/lib/vaultlink".into(),
            internal_directory: Some("/mnt/.vaultlink-internal".into()),
            require_mount: true,
            external_writers: true,
            allow_external_writer_replace: false,
            expected_filesystem_type: Some("cifs".into()),
            expected_mount_source: Some("//nas.example/vault link".into()),
            max_upload_size: 1,
            max_zip_size: 0,
            max_zip_files: 0,
            max_search_entries: 1,
            max_search_results: 1,
            max_preview_size: 1,
            preview_extensions: vec![],
            image_preview_extensions: vec![],
            pdf_preview_enabled: false,
            max_media_preview_size: 1,
            blocked_extensions: vec![],
        }
    }

    fn mounts() -> Vec<MountInfo> {
        parse_mountinfo(
            b"41 23 0:42 / /mnt rw,nosuid,nodev,noexec,relatime - cifs //nas.example/vault\\040link rw,vers=3.1.1,cache=strict,sign,seal,serverino\n\
              23 1 8:2 / / rw,relatime - ext4 /dev/sda2 rw\n",
        )
        .unwrap()
    }

    fn identity(mount_id: u64, device_major: u32, device_minor: u32) -> PathMountIdentity {
        PathMountIdentity {
            mount_id,
            device_major,
            device_minor,
        }
    }

    fn location(
        path: &'static str,
        mount_id: u64,
        device_major: u32,
        device_minor: u32,
    ) -> IdentifiedPath<'static> {
        identified(
            Path::new(path),
            identity(mount_id, device_major, device_minor),
        )
    }

    fn unmounted_storage(root: &Path, data: &Path) -> Storage {
        let mut storage = storage();
        storage.root_mount_path = root.to_path_buf();
        storage.data_directory = data.to_path_buf();
        storage.internal_directory = None;
        storage.require_mount = false;
        storage.external_writers = false;
        storage.expected_filesystem_type = None;
        storage.expected_mount_source = None;
        storage
    }

    #[test]
    fn discovers_supported_read_write_mounts_and_filters_weak_cifs() {
        let detected = discover_supported_mounts_from(
            b"41 23 0:42 / /mnt/storage rw,nosuid,nodev,noexec - cifs //nas.example/vault rw,vers=3.1.1,cache=strict,sign,seal,serverino\n\
              42 23 0:43 / /mnt/weak rw,nosuid,nodev,noexec - cifs //nas.example/weak rw,vers=3.0,cache=loose,noserverino\n\
              43 23 0:44 / /mnt/read-only ro,nosuid,nodev,noexec - cifs //nas.example/readonly ro,vers=3.1.1,cache=strict,sign,seal,serverino\n\
              44 23 8:2 / /mnt/local rw,nosuid,nodev,noexec - ext4 /dev/mapper/storage rw\n\
              45 23 0:45 / /mnt/overlay rw,nosuid,nodev,noexec - overlay overlay rw\n",
        )
        .unwrap();
        assert_eq!(
            detected,
            vec![
                DetectedMount {
                    mount_point: "/mnt/local".into(),
                    root_mount_path: "/mnt/local/shared".into(),
                    internal_directory: "/mnt/local/.vaultlink-internal".into(),
                    filesystem_type: "ext4".into(),
                    source: "/dev/mapper/storage".into(),
                },
                DetectedMount {
                    mount_point: "/mnt/storage".into(),
                    root_mount_path: "/mnt/storage".into(),
                    internal_directory: "/mnt/storage/.vaultlink-internal".into(),
                    filesystem_type: "cifs".into(),
                    source: "//nas.example/vault".into(),
                },
            ]
        );
    }

    #[test]
    fn normalizes_smb3_mountinfo_to_the_cifs_policy_name() {
        let detected = discover_supported_mounts_from(
            b"41 23 0:42 / /mnt/storage rw,nosuid,nodev,noexec - smb3 //nas.example/vault rw,vers=3.1.1,cache=strict,sign,seal,serverino\n",
        )
        .unwrap();
        assert_eq!(detected[0].filesystem_type, "cifs");
        assert!(filesystem_types_match("smb3", "cifs"));
        assert!(filesystem_types_match("cifs", "smb3"));
    }

    #[test]
    fn mount_point_filter_rejects_file_mount_targets() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("hosts");
        std::fs::write(&file, b"127.0.0.1 localhost\n").unwrap();
        assert!(mount_point_is_directory(directory.path()));
        assert!(!mount_point_is_directory(&file));
    }

    #[test]
    fn active_mount_lookup_requires_one_exact_utf8_mount_point() {
        let mountinfo = b"41 23 0:42 / /mnt/storage rw,nosuid,nodev,noexec - cifs //nas.example/vault rw,vers=3.1.1,cache=strict,sign,seal,serverino\n\
              23 1 8:2 / / rw,relatime - ext4 /dev/sda2 rw\n";
        let active = active_mount_at_from(mountinfo, Path::new("/mnt/storage"))
            .unwrap()
            .unwrap();
        assert_eq!(active.filesystem_type, "cifs");
        assert_eq!(active.source, "//nas.example/vault");
        assert!(active.read_write);
        assert!(active_mount_at_from(mountinfo, Path::new("/mnt/missing"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn parses_escaped_mount_identity() {
        let mounts = mounts();
        assert_eq!(mounts[0].mount_id, 41);
        assert_eq!(mounts[0].mount_point, Path::new("/mnt"));
        assert!(mounts[0].read_write);
        assert_eq!(mounts[0].filesystem_type, "cifs");
        assert_eq!(mounts[0].source, OsStr::new("//nas.example/vault link"));
    }

    #[test]
    fn validated_root_capability_detects_a_path_replacement() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("root");
        let displaced = parent.path().join("root-validated");
        let data = parent.path().join("data");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&data).unwrap();
        let storage = unmounted_storage(&root, &data);
        let validated = validate_and_open(&storage).unwrap();

        std::fs::rename(&root, &displaced).unwrap();
        std::fs::create_dir(&root).unwrap();

        let error = validated.verify_path_bindings(&storage).unwrap_err();
        assert!(error.to_string().contains("root_mount_path"));
        assert_eq!(
            validated.root.file.metadata().unwrap().ino(),
            std::fs::metadata(&displaced).unwrap().ino()
        );
        assert_ne!(
            validated.root.file.metadata().unwrap().ino(),
            std::fs::metadata(&root).unwrap().ino()
        );
    }

    #[test]
    fn validated_data_capability_detects_a_path_replacement() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("root");
        let data = parent.path().join("data");
        let displaced = parent.path().join("data-validated");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&data).unwrap();
        let storage = unmounted_storage(&root, &data);
        let validated = validate_and_open(&storage).unwrap();

        std::fs::rename(&data, &displaced).unwrap();
        std::fs::create_dir(&data).unwrap();

        let error = validated.verify_path_bindings(&storage).unwrap_err();
        assert!(error.to_string().contains("data_directory"));
        assert_eq!(
            validated.data.file.metadata().unwrap().ino(),
            std::fs::metadata(&displaced).unwrap().ino()
        );
        assert_ne!(
            validated.data.file.metadata().unwrap().ino(),
            std::fs::metadata(&data).unwrap().ino()
        );
    }

    #[test]
    fn accepts_exact_mount_and_separate_data_mount_ids() {
        validate_identity(
            &storage(),
            location("/mnt/vault link", 41, 0, 42),
            location("/mnt/.vaultlink-internal", 41, 0, 42),
            location("/var/lib", 23, 8, 2),
            &mounts(),
        )
        .unwrap();
    }

    #[test]
    fn accepts_btrfs_cooked_device_for_an_exact_mount_id() {
        let btrfs_mounts = parse_mountinfo(
            b"41 23 253:16 / /mnt/storage rw,nosuid,nodev - ext4 /dev/vdb rw\n\
              23 1 0:32 /var /var rw,relatime - btrfs /dev/vda3 rw,subvol=/var\n",
        )
        .unwrap();
        let mut local = storage();
        local.root_mount_path = "/mnt/storage/shared".into();
        local.internal_directory = Some("/mnt/storage/.vaultlink-internal".into());
        local.data_directory = "/var/lib/vaultlink".into();
        local.external_writers = false;
        local.expected_filesystem_type = Some("ext4".into());
        local.expected_mount_source = Some("/dev/vdb".into());

        validate_identity(
            &local,
            location("/mnt/storage/shared", 41, 253, 16),
            location("/mnt/storage/.vaultlink-internal", 41, 253, 16),
            // Btrfs reports a per-subvolume st_dev (0:50), while mountinfo
            // reports the raw superblock device (0:32) for the same mount ID.
            location("/var/lib/vaultlink", 23, 0, 50),
            &btrfs_mounts,
        )
        .unwrap();
    }

    #[test]
    fn mount_lookup_rejects_absent_duplicate_and_unrelated_mount_ids() {
        let parsed = mounts();
        let absent =
            unique_mount_for_identity(identity(99, 8, 2), &parsed, Path::new("/var/lib/vaultlink"))
                .unwrap_err();
        assert!(absent.to_string().contains("is absent"));

        let mut duplicate = parsed.clone();
        duplicate.push(duplicate[1].clone());
        let repeated = unique_mount_for_identity(
            identity(23, 8, 2),
            &duplicate,
            Path::new("/var/lib/vaultlink"),
        )
        .unwrap_err();
        assert!(repeated.to_string().contains("occurs more than once"));

        let unrelated = unique_mount_for_identity(
            identity(41, 0, 42),
            &parsed,
            Path::new("/srv/not-on-the-share"),
        )
        .unwrap_err();
        assert!(unrelated.to_string().contains("not below"));
    }

    #[test]
    fn accepts_cifs_share_root_with_direct_reserved_internal_child() {
        let mut nested = storage();
        nested.root_mount_path = "/mnt/storage".into();
        nested.internal_directory = Some("/mnt/storage/.vaultlink-internal".into());
        nested.expected_mount_source = Some("//nas.example/vault".into());
        let mounts = parse_mountinfo(
            b"41 23 0:42 / /mnt/storage rw,nosuid,nodev,noexec - cifs //nas.example/vault rw,vers=3.1.1,cache=strict,sign,seal,serverino\n\
              23 1 8:2 / / rw,relatime - ext4 /dev/sda2 rw\n",
        )
        .unwrap();

        validate_identity(
            &nested,
            location("/mnt/storage", 41, 0, 42),
            location("/mnt/storage/.vaultlink-internal", 41, 0, 42),
            location("/var/lib", 23, 8, 2),
            &mounts,
        )
        .unwrap();
    }

    #[test]
    fn accepts_audited_local_storage_and_sqlite_on_the_same_mount() {
        let local_mounts = parse_mountinfo(
            b"23 1 8:2 / / rw,nosuid,nodev,relatime - ext4 /dev/mapper/vaultlink rw\n",
        )
        .unwrap();
        let mut local = storage();
        local.root_mount_path = "/srv/vaultlink/shared".into();
        local.internal_directory = Some("/srv/vaultlink/.vaultlink-internal".into());
        local.data_directory = "/var/lib/vaultlink".into();
        local.external_writers = false;
        local.expected_filesystem_type = Some("ext4".into());
        local.expected_mount_source = Some("/dev/mapper/vaultlink".into());

        validate_identity(
            &local,
            location("/srv/vaultlink/shared", 23, 8, 2),
            location("/srv/vaultlink/.vaultlink-internal", 23, 8, 2),
            location("/var/lib/vaultlink", 23, 8, 2),
            &local_mounts,
        )
        .unwrap();
    }

    #[test]
    fn rejects_local_filesystems_outside_the_audited_allowlist() {
        let overlay_mounts = parse_mountinfo(
            b"23 1 0:99 / / rw,nosuid,nodev - overlay overlay rw,lowerdir=/lower,upperdir=/upper,workdir=/work\n",
        )
        .unwrap();
        let mut local = storage();
        local.root_mount_path = "/srv/vaultlink/shared".into();
        local.internal_directory = Some("/srv/vaultlink/.vaultlink-internal".into());
        local.data_directory = "/var/lib/vaultlink".into();
        local.external_writers = false;
        local.expected_filesystem_type = Some("overlay".into());
        local.expected_mount_source = Some("overlay".into());

        let error = validate_identity(
            &local,
            location("/srv/vaultlink/shared", 23, 0, 99),
            location("/srv/vaultlink/.vaultlink-internal", 23, 0, 99),
            location("/var/lib/vaultlink", 23, 0, 99),
            &overlay_mounts,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("no audited VaultLink mount policy"));
    }

    #[test]
    fn rejects_a_canonical_data_directory_inside_the_visible_root() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("shared");
        let internal = directory.path().join(".vaultlink-internal");
        let data = root.join("state");
        let data_alias = directory.path().join("state-alias");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&internal).unwrap();
        std::fs::create_dir(&data).unwrap();
        symlink(&data, &data_alias).unwrap();

        let error = validate_canonical_relationships(
            &root.canonicalize().unwrap(),
            &internal.canonicalize().unwrap(),
            &data_alias.canonicalize().unwrap(),
            false,
        )
        .unwrap_err();
        assert!(error.to_string().contains("user-visible root_mount_path"));
    }

    #[test]
    fn accepts_only_the_direct_reserved_child_for_nested_internal_storage() {
        let root = Path::new("/mnt/storage");
        assert!(validate_internal_relationship(
            root,
            Path::new("/mnt/storage/.vaultlink-internal"),
            true,
        )
        .is_ok());
        assert!(validate_internal_relationship(
            root,
            Path::new("/mnt/storage/data/.vaultlink-internal"),
            true,
        )
        .is_err());
        assert!(validate_internal_relationship(
            root,
            Path::new("/mnt/storage/.vaultlink-internal"),
            false,
        )
        .is_err());
    }

    #[test]
    fn rejects_group_or_acl_mask_writable_service_directories() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        let error =
            validate_service_owned_directory(directory.path(), "root_mount_path").unwrap_err();
        assert!(error.to_string().contains("POSIX ACL mask"));

        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
        validate_service_owned_directory(directory.path(), "root_mount_path").unwrap();
    }

    #[test]
    fn rejects_local_fallback_wrong_source_and_wrong_type() {
        let mut local_fallback = mounts();
        local_fallback[0].filesystem_type = "ext4".into();
        local_fallback[0].source = "/dev/sdb1".into();
        let error = validate_identity(
            &storage(),
            location("/mnt/vault link", 41, 0, 42),
            location("/mnt/.vaultlink-internal", 41, 0, 42),
            location("/var/lib", 23, 8, 2),
            &local_fallback,
        )
        .unwrap_err();
        assert!(error.to_string().contains("filesystem type"));

        let mut wrong_source = storage();
        wrong_source.expected_mount_source = Some("//other.example/vault".into());
        let error = validate_identity(
            &wrong_source,
            location("/mnt/vault link", 41, 0, 42),
            location("/mnt/.vaultlink-internal", 41, 0, 42),
            location("/var/lib", 23, 8, 2),
            &mounts(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("mount source"));
    }

    #[test]
    fn rejects_read_only_external_mount() {
        let mut read_only = mounts();
        read_only[0].read_write = false;
        let error = validate_identity(
            &storage(),
            location("/mnt/vault link", 41, 0, 42),
            location("/mnt/.vaultlink-internal", 41, 0, 42),
            location("/var/lib", 23, 8, 2),
            &read_only,
        )
        .unwrap_err();
        assert!(error.to_string().contains("read-only"));
    }

    #[test]
    fn rejects_weak_or_incoherent_cifs_options() {
        for forbidden in ["cache=loose", "nostrictsync", "noperm", "multiuser"] {
            let mut weak = mounts();
            weak[0].super_options.push(forbidden.into());
            let error = validate_identity(
                &storage(),
                location("/mnt/vault link", 41, 0, 42),
                location("/mnt/.vaultlink-internal", 41, 0, 42),
                location("/var/lib", 23, 8, 2),
                &weak,
            )
            .unwrap_err();
            assert!(error.to_string().contains("forbidden option"));
        }

        let mut missing_encryption = mounts();
        missing_encryption[0]
            .super_options
            .retain(|option| option != "seal");
        let error = validate_identity(
            &storage(),
            location("/mnt/vault link", 41, 0, 42),
            location("/mnt/.vaultlink-internal", 41, 0, 42),
            location("/var/lib", 23, 8, 2),
            &missing_encryption,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("missing required security option"));
    }

    #[test]
    fn rejects_network_filesystem_for_sqlite() {
        let mut remote_data = mounts();
        remote_data[1].filesystem_type = "nfs4".into();
        remote_data[1].source = "nas:/state".into();
        let error = validate_identity(
            &storage(),
            location("/mnt/vault link", 41, 0, 42),
            location("/mnt/.vaultlink-internal", 41, 0, 42),
            location("/var/lib", 23, 8, 2),
            &remote_data,
        )
        .unwrap_err();
        assert!(error.to_string().contains("SQLite/WAL"));
    }

    #[test]
    fn rejects_path_outside_the_validated_mountpoint() {
        let error = validate_identity(
            &storage(),
            location("/srv/local-fallback", 41, 0, 42),
            location("/mnt/.vaultlink-internal", 41, 0, 42),
            location("/var/lib", 23, 8, 2),
            &mounts(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("not below"));
    }

    #[test]
    fn rejects_sqlite_state_on_same_mount_id() {
        let error = validate_identity(
            &storage(),
            location("/mnt/vault link", 41, 0, 42),
            location("/mnt/.vaultlink-internal", 41, 0, 42),
            location("/mnt/vault link/.state", 41, 0, 42),
            &mounts(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("SQLite state"));
    }

    #[test]
    fn rejects_bind_mount_of_same_external_filesystem_for_sqlite() {
        let error = validate_identity(
            &storage(),
            location("/mnt/vault link", 41, 0, 42),
            location("/mnt/.vaultlink-internal", 41, 0, 42),
            location("/var/lib/vaultlink", 99, 0, 42),
            &mounts(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("same external mount identity"));
    }

    #[test]
    fn malformed_mountinfo_fails_closed() {
        assert!(parse_mountinfo(b"41 incomplete\n").is_err());
        assert!(parse_mountinfo(b"41 23 0:42 / /mnt/bad\\99 rw - cifs //nas/share rw\n").is_err());
    }
}
