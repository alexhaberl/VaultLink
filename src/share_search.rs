#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ShareSearchError {
    TooShort,
    TooLong,
}

impl ShareSearchError {
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::TooShort => "Share search requires at least three characters",
            Self::TooLong => "Share search query is too long",
        }
    }
}

/// Validate user characters before case folding can expand a short term.
pub(crate) fn validate_share_search(query: Option<&str>) -> Result<Option<&str>, ShareSearchError> {
    let Some(query) = query.map(str::trim).filter(|query| !query.is_empty()) else {
        return Ok(None);
    };
    if query.len() > crate::http_contract::MAX_SEARCH_QUERY_BYTES {
        return Err(ShareSearchError::TooLong);
    }
    if query.chars().count() < 3 {
        return Err(ShareSearchError::TooShort);
    }
    Ok(Some(query))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_unicode_short_and_byte_limits_are_explicit() {
        assert_eq!(validate_share_search(None), Ok(None));
        assert_eq!(validate_share_search(Some(" \t ")), Ok(None));
        for value in ["a", "ab", "ßa", "界界", "  ab  "] {
            assert_eq!(
                validate_share_search(Some(value)),
                Err(ShareSearchError::TooShort)
            );
        }
        assert_eq!(validate_share_search(Some("  Äß界  ")), Ok(Some("Äß界")));
        assert_eq!(
            validate_share_search(Some(&"a".repeat(257))),
            Err(ShareSearchError::TooLong)
        );
        assert!(validate_share_search(Some(&"a".repeat(256))).is_ok());
        assert_eq!(
            validate_share_search(Some(&"界".repeat(86))),
            Err(ShareSearchError::TooLong)
        );
    }
}
