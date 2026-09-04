use super::{
    insert_required_audits, token_hash, trace_required_audits, AuditAction, AuditContext, Audited,
    Database, MfaSessionProof, Permission, RequiredAuditEvent, SessionBound, Share,
    ShareControlsUpdateOutcome, ShareListOptions, ShareListSort, SharePage, ShareSummary,
    UploadConflictStrategy, MAX_SQLITE_UNSIGNED,
};
#[cfg(test)]
use super::{DEFAULT_SHARE_UPLOAD_FILE_COUNT, DEFAULT_SHARE_UPLOAD_TOTAL_SIZE};
use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension, TransactionBehavior};

pub(crate) type AuditedShareControlsUpdate =
    SessionBound<Audited<(ShareControlsUpdateOutcome, Option<Share>)>>;

#[cfg(test)]
thread_local! {
    static SHARE_MAP_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(any(test, feature = "fuzzing"))]
pub fn rewrite_share_path(
    candidate: &str,
    target: &str,
    replacement: &str,
    is_directory: bool,
) -> Option<String> {
    if candidate == target {
        return Some(replacement.to_string());
    }
    if !is_directory {
        return None;
    }
    candidate
        .strip_prefix(target)
        .filter(|suffix| suffix.starts_with('/'))
        .map(|suffix| format!("{replacement}{suffix}"))
}

fn glob_literal(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '*' => escaped.push_str("[*]"),
            '?' => escaped.push_str("[?]"),
            '[' => escaped.push_str("[[]"),
            ']' => escaped.push_str("[]]"),
            character => escaped.push(character),
        }
    }
    escaped
}

fn path_globs(path: &str) -> (String, String) {
    let exact = glob_literal(path);
    let subtree = format!("{exact}/*");
    (exact, subtree)
}

include!("shares/query.rs");
include!("shares/mutations.rs");

fn fts5_phrase(value: &str) -> String {
    let mut phrase = String::with_capacity(value.len().saturating_add(2));
    phrase.push('"');
    for character in value.chars() {
        if character == '"' {
            phrase.push('"');
        }
        phrase.push(character);
    }
    phrase.push('"');
    phrase
}

pub(super) fn unicode_search_key(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    for character in value.chars().flat_map(char::to_lowercase) {
        // Rust's lowercase mapping is Unicode-aware but is not a full case
        // fold. Normalize sharp-s as well so common German searches such as
        // "GRÜS" match "Grüße" after the remaining Unicode lowercase pass.
        if character == 'ß' {
            normalized.push_str("ss");
        } else {
            normalized.push(character);
        }
    }
    normalized
}

#[cfg(test)]
pub(super) fn reset_share_map_count() {
    SHARE_MAP_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(super) fn share_map_count() -> usize {
    SHARE_MAP_COUNT.with(std::cell::Cell::get)
}
