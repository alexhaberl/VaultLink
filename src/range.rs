/// Parses one RFC 7233 byte range. Multiple ranges are deliberately unsupported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RangeError;

pub fn parse_byte_range(value: &str, length: u64) -> Result<(u64, u64), RangeError> {
    if length == 0 || !value.starts_with("bytes=") || value.contains(',') {
        return Err(RangeError);
    }
    let (start, end) = value[6..].split_once('-').ok_or(RangeError)?;
    let (start, end) = if start.is_empty() {
        let suffix = end.parse::<u64>().map_err(|_| RangeError)?;
        if suffix == 0 {
            return Err(RangeError);
        }
        (length.saturating_sub(suffix), length - 1)
    } else {
        let start = start.parse::<u64>().map_err(|_| RangeError)?;
        let end = if end.is_empty() {
            length - 1
        } else {
            end.parse::<u64>().map_err(|_| RangeError)?.min(length - 1)
        };
        (start, end)
    };
    if start >= length || end < start {
        return Err(RangeError);
    }
    Ok((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_ranges() {
        assert_eq!(parse_byte_range("bytes=0-9", 100), Ok((0, 9)));
        assert_eq!(parse_byte_range("bytes=90-", 100), Ok((90, 99)));
        assert_eq!(parse_byte_range("bytes=-10", 100), Ok((90, 99)));
        assert!(parse_byte_range("bytes=100-101", 100).is_err());
        assert!(parse_byte_range("bytes=0-1,3-4", 100).is_err());
    }
}
