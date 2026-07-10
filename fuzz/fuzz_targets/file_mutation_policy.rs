#![no_main]

use libfuzzer_sys::fuzz_target;
use vaultlink::{db, file_ops, path_security};

fuzz_target!(
    |input: (String, String, String, String, Option<String>, bool)| {
        let (path, new_name, share_path, replacement, confirmation, is_directory) = input;

        if let Ok(plan) = file_ops::plan_rename(&path, &new_name) {
            assert!(!plan.path.is_empty());
            assert_ne!(plan.path, plan.destination);
            assert_eq!(plan.new_name, new_name);
            assert!(path_security::validate_relative(&plan.path).is_ok());
            assert!(path_security::validate_relative(&plan.destination).is_ok());
            assert!(path_security::safe_admin_filename(&plan.new_name).is_ok());
            let old_parent = plan.path.rsplit_once('/').map_or("", |(parent, _)| parent);
            let new_parent = plan
                .destination
                .rsplit_once('/')
                .map_or("", |(parent, _)| parent);
            assert_eq!(old_parent, new_parent);
        }

        let normalized_target = path_security::validate_relative(&path)
            .ok()
            .map(|path| path.to_string_lossy().replace('\\', "/"));
        if let Some(target) = normalized_target.as_deref().filter(|path| !path.is_empty()) {
            let rewritten = db::rewrite_share_path(&share_path, target, &replacement, is_directory);
            if let Some(rewritten) = rewritten {
                assert!(
                    share_path == target
                        || (is_directory
                            && share_path
                                .strip_prefix(target)
                                .is_some_and(|suffix| suffix.starts_with('/')))
                );
                assert!(rewritten.starts_with(&replacement));
                assert_eq!(
                    rewritten.strip_prefix(&replacement),
                    share_path.strip_prefix(target)
                );
            }

            let result = file_ops::validate_delete_confirmation(
                target,
                is_directory,
                confirmation.as_deref(),
            );
            assert_eq!(
                result.is_ok(),
                !is_directory || confirmation.as_deref() == target.rsplit('/').next()
            );
        }
    }
);
