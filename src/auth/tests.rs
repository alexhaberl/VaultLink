mod tests {
    use super::*;

    // Generated with argon2 0.5.3/password-hash 0.5.0. Keep these fixed so
    // compatibility is tested against hashes created by the previous version.
    const ARGON2_0_5_ALTERNATE_PARAMS_FIXTURE: &str =
        "$argon2id$v=19$m=4096,t=3,p=1$MDEyMzQ1Njc4OWFiY2RlZg$ZIgZc5Em9MHrC+H07onKRLx1wU3GrciA1ragq7pWz6o";
    const ARGON2_0_5_CURRENT_PARAMS_FIXTURE: &str =
        "$argon2id$v=19$m=19456,t=2,p=1$MDEyMzQ1Njc4OWFiY2RlZg$gy5SuVm5Z7Vw7keB9se9p87QGcomaseB/S2U1OhTsM0";
    const TAMPERED_ARGON2_0_5_FIXTURE: &str =
        "$argon2id$v=19$m=4096,t=3,p=1$MDEyMzQ1Njc4OWFiY2RlZg$ZIgZc5Em9MHrC+H07onKRLx1wU3GrciA1ragq7pWz6s";

    fn assert_current_password_hash_shape(hash: &str) {
        let parsed = PasswordHash::new(hash).unwrap();
        assert_eq!(parsed.algorithm.as_str(), "argon2id");
        assert_eq!(parsed.version, Some(19));
        assert_eq!(parsed.params.get_decimal("m"), Some(19_456));
        assert_eq!(parsed.params.get_decimal("t"), Some(2));
        assert_eq!(parsed.params.get_decimal("p"), Some(1));
        assert_eq!(parsed.salt.as_ref().map(|salt| salt.len()), Some(16));
        assert_eq!(parsed.hash.as_ref().map(|output| output.len()), Some(32));
    }

    #[test]
    fn constant_time_token_comparison_handles_equal_different_and_mismatched_lengths() {
        assert!(constant_time_eq("same-token", "same-token"));
        assert!(!constant_time_eq("same-token", "same-taken"));
        assert!(!constant_time_eq("same-token", "short"));
    }

    #[test]
    fn password_round_trip() {
        let first = hash_password("correct horse battery staple").unwrap();
        let second = hash_password("correct horse battery staple").unwrap();
        assert_current_password_hash_shape(&first);
        assert_current_password_hash_shape(&second);
        assert_ne!(first, second);
        assert!(verify_password(&first, "correct horse battery staple"));
        assert!(verify_password(&second, "correct horse battery staple"));
        assert!(!verify_password(&first, "wrong"));
        assert!(!verify_password(
            &first,
            &"x".repeat(MAX_PASSWORD_BYTES + 1)
        ));
    }

    #[test]
    fn password_verification_accepts_argon2_0_5_fixtures() {
        assert!(verify_password(
            ARGON2_0_5_ALTERNATE_PARAMS_FIXTURE,
            "legacy password"
        ));
        assert!(verify_password(
            ARGON2_0_5_CURRENT_PARAMS_FIXTURE,
            "correct horse battery staple"
        ));
        assert!(!verify_password(
            ARGON2_0_5_ALTERNATE_PARAMS_FIXTURE,
            "wrong"
        ));
        assert!(!verify_password(ARGON2_0_5_CURRENT_PARAMS_FIXTURE, "wrong"));
    }

    #[test]
    fn password_verification_rejects_tampered_or_invalid_hashes() {
        assert!(PasswordHash::new(TAMPERED_ARGON2_0_5_FIXTURE).is_ok());
        assert!(!verify_password(
            TAMPERED_ARGON2_0_5_FIXTURE,
            "legacy password"
        ));
        assert!(!verify_password("not-a-phc-string", "legacy password"));
    }

    #[test]
    fn admin_password_policy_has_consistent_character_and_byte_boundaries() {
        assert!(!valid_admin_password(
            &"ä".repeat(ADMIN_PASSWORD_MIN_CHARACTERS - 1)
        ));
        assert!(valid_admin_password(
            &"ä".repeat(ADMIN_PASSWORD_MIN_CHARACTERS)
        ));
        assert!(valid_admin_password(
            &"x".repeat(ADMIN_PASSWORD_MAX_CHARACTERS)
        ));
        assert!(!valid_admin_password(
            &"x".repeat(ADMIN_PASSWORD_MAX_CHARACTERS + 1)
        ));
        assert!(valid_admin_password(
            &"🔑".repeat(ADMIN_PASSWORD_MAX_CHARACTERS)
        ));
    }

    #[test]
    fn generated_tokens_and_totp_secrets_have_expected_lengths() {
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(random_token(32).as_bytes())
                .unwrap()
                .len(),
            32
        );
        assert_eq!(
            BASE32_NOPAD
                .decode(new_totp_secret().as_bytes())
                .unwrap()
                .len(),
            20
        );
    }
    #[test]
    fn rfc_totp() {
        let secret = concat!("GEZDGNBV", "GY3TQOJQ", "GEZDGNBV", "GY3TQOJQ");
        assert!(verify_totp(secret, "287082", 59));
        assert_eq!(matching_totp_step(secret, "287082", 59), Some(1));
        assert_eq!(matching_totp_step(secret, "not-a-code", 59), None);
    }
    #[test]
    fn limiter_blocks() {
        let l = LoginLimiter::new(2, Duration::from_secs(60));
        assert!(l.check_and_record_attempt("x"));
        assert!(l.check_and_record_attempt("x"));
        assert!(!l.check_and_record_attempt("x"));
        l.success("x");
        assert!(l.check_and_record_attempt("x"));
    }

    #[test]
    fn limiter_check_and_record_is_atomic() {
        use std::sync::Barrier;
        use std::thread;

        let limiter = LoginLimiter::new(3, Duration::from_secs(60));
        let barrier = Arc::new(Barrier::new(16));
        let handles = (0..16)
            .map(|_| {
                let limiter = limiter.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    limiter.check_and_record_attempt("same-key")
                })
            })
            .collect::<Vec<_>>();

        let admitted = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|admitted| *admitted)
            .count();
        assert_eq!(admitted, 3);
    }

    #[test]
    fn limiter_recovers_after_lock_poisoning() {
        let limiter = LoginLimiter::new(2, Duration::from_secs(60));
        let poisoned = limiter.clone();
        let panic = std::panic::catch_unwind(move || {
            let _guard = poisoned.inner.lock().unwrap();
            panic!("inject limiter lock poisoning");
        });
        assert!(panic.is_err());
        assert!(limiter.inner.is_poisoned());

        assert!(limiter.check_and_record_attempt("after-panic"));
        assert!(!limiter.inner.is_poisoned());
    }

    #[test]
    fn limiter_bounds_structurally_invalid_poisoned_state_fail_closed() {
        let limiter = LoginLimiter::with_capacity_and_overflow(2, Duration::from_secs(60), 1, 2);
        let poisoned = limiter.clone();
        let panic = std::panic::catch_unwind(move || {
            let mut state = poisoned.inner.lock().unwrap();
            state.entries.insert(
                "one".into(),
                AttemptHistory {
                    attempts: vec![Instant::now()],
                },
            );
            state.entries.insert(
                "two".into(),
                AttemptHistory {
                    attempts: vec![Instant::now()],
                },
            );
            state.overflow.clear();
            panic!("inject invalid limiter state");
        });
        assert!(panic.is_err());

        assert!(!limiter.check_and_record_attempt("new-key"));
        let state = limiter.inner.lock().unwrap();
        assert!(state.entries.is_empty());
        assert_eq!(state.overflow.len(), 2);
        assert!(state
            .overflow
            .iter()
            .flatten()
            .all(|history| history.attempts.len() == 2));
        assert!(!limiter.inner.is_poisoned());
    }

    #[test]
    fn limiter_records_multiple_keys_all_or_nothing() {
        let limiter = LoginLimiter::new(1, Duration::from_secs(60));
        assert!(limiter.check_and_record_attempt("blocked"));
        assert!(!limiter.check_and_record_attempts(&["new", "blocked"]));

        let state = limiter.inner.lock().unwrap();
        assert!(!state.entries.contains_key("new"));
    }

    #[test]
    fn limiter_never_evicts_active_primary_histories() {
        let limiter = LoginLimiter::with_capacity_and_overflow(1, Duration::from_secs(60), 1, 4);
        assert!(limiter.check_and_record_attempt("victim"));
        for index in 0..1_000 {
            let _ = limiter.check_and_record_attempt(&format!("churn-{index}"));
        }

        assert!(!limiter.check_and_record_attempt("victim"));
        let state = limiter.inner.lock().unwrap();
        assert_eq!(state.entries.len(), 1);
        assert!(state.entries.contains_key("victim"));
    }

    #[test]
    fn limiter_bounds_new_keys_in_overflow_without_clearing_collisions() {
        let limiter = LoginLimiter::with_capacity_and_overflow(2, Duration::from_secs(60), 1, 1);
        assert!(limiter.check_and_record_attempt("primary"));
        assert!(limiter.check_and_record_attempt("overflow-a"));
        assert!(limiter.check_and_record_attempt("overflow-b"));

        limiter.success("overflow-a");
        limiter.success("unrelated-key");
        assert!(!limiter.check_and_record_attempt("overflow-b"));

        let state = limiter.inner.lock().unwrap();
        assert_eq!(state.entries.len(), 1);
        assert!(state.entries.contains_key("primary"));
        assert!(state
            .entries
            .values()
            .all(|history| !history.attempts.is_empty()));
        assert!(state
            .overflow
            .iter()
            .flatten()
            .all(|history| !history.attempts.is_empty()));
    }

    #[test]
    fn invalid_limiter_configuration_fails_closed() {
        let no_attempts = LoginLimiter::new(0, Duration::from_secs(60));
        assert!(!no_attempts.check_and_record_attempt("x"));

        let no_window = LoginLimiter::new(2, Duration::ZERO);
        assert!(!no_window.check_and_record_attempt("x"));
    }

    #[test]
    fn unknown_username_churn_cannot_consume_known_admin_counters() {
        let limiter = AdminLoginLimiter::new(["Admin".to_string()], 2, 2, Duration::from_secs(60));
        let origin = "192.0.2.1".parse().unwrap();
        assert!(limiter.check_and_record_attempt("ADMIN", origin));

        for index in 0..50_000 {
            let _ = limiter.check_and_record_attempt(
                &format!("random-{index}"),
                "198.51.100.10".parse().unwrap(),
            );
        }

        assert!(limiter.check_and_record_attempt("admin", origin));
        assert!(!limiter.check_and_record_attempt("admin", origin));
    }

    #[test]
    fn unknown_admin_limiter_state_stays_fixed_size_under_concurrency() {
        use std::{sync::Barrier, thread};

        let limiter = AdminLoginLimiter::new([], 5, 10, Duration::from_secs(60));
        let barrier = Arc::new(Barrier::new(16));
        let handles = (0..16)
            .map(|worker| {
                let limiter = limiter.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    for attempt in 0..2_000 {
                        let username = format!("unknown-{worker}-{attempt}");
                        let origin = format!("198.51.{}.{}", worker + 1, attempt % 250 + 1)
                            .parse()
                            .unwrap();
                        let _ = limiter.check_and_record_attempt(&username, origin);
                    }
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(
            limiter.state_sizes(),
            (
                0,
                0,
                UNKNOWN_ADMIN_ACCOUNT_BUCKETS,
                UNKNOWN_ADMIN_IP_BUCKETS
            )
        );
    }

    #[test]
    fn exhausted_admin_account_budget_does_not_grow_origin_state() {
        let limiter = AdminLoginLimiter::new(["admin".to_string()], 5, 1, Duration::from_secs(60));
        assert!(limiter.check_and_record_attempt("admin", "192.0.2.1".parse().unwrap()));
        let sizes = limiter.state_sizes();
        assert!(!limiter.check_and_record_attempt("admin", "192.0.2.2".parse().unwrap()));
        assert_eq!(limiter.state_sizes(), sizes);

        let unknown = AdminLoginLimiter::new([], 5, 1, Duration::from_secs(60));
        assert!(unknown.check_and_record_attempt("unknown", "198.51.100.1".parse().unwrap()));
        let used_ip_buckets = unknown.used_unknown_ip_buckets();
        assert!(!unknown.check_and_record_attempt("unknown", "203.0.113.1".parse().unwrap()));
        assert_eq!(unknown.used_unknown_ip_buckets(), used_ip_buckets);
    }

    #[test]
    fn known_admins_keep_per_origin_and_global_account_limits() {
        let limiter = AdminLoginLimiter::new(["admin".to_string()], 2, 4, Duration::from_secs(60));
        let first = "192.0.2.1".parse().unwrap();
        let second = "192.0.2.2".parse().unwrap();
        assert!(limiter.check_and_record_attempt("admin", first));
        assert!(limiter.check_and_record_attempt("admin", first));
        assert!(!limiter.check_and_record_attempt("admin", first));
        assert!(limiter.check_and_record_attempt("admin", second));
        assert!(limiter.check_and_record_attempt("admin", second));
        assert!(!limiter.check_and_record_attempt("admin", second));
    }

    #[test]
    fn admin_username_policy_is_bounded_safe_ascii() {
        assert!(valid_admin_username("admin-_01"));
        assert!(valid_admin_username(&"a".repeat(64)));
        assert!(!valid_admin_username("ab"));
        assert!(!valid_admin_username(&"a".repeat(65)));
        assert!(!valid_admin_username("admin.name"));
        assert!(!valid_admin_username("admin name"));
        assert!(!valid_admin_username("\u{00e4}dmin"));
    }
}
