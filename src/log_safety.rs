use std::fmt;

/// A path-like value that is safe to render into a single-line tracing field.
///
/// This wrapper is deliberately crate-private and exposes no accessor for the
/// wrapped value. `Debug` and `Display` both escape control characters so a
/// later change from `%value` to `?value` cannot reintroduce log injection.
#[must_use]
pub(crate) struct EscapedLogPath<'a, T: ?Sized>(&'a T);

impl<'a, T: ?Sized> EscapedLogPath<'a, T> {
    pub(crate) fn new(value: &'a T) -> Self {
        Self(value)
    }
}

impl<T: fmt::Display + ?Sized> fmt::Display for EscapedLogPath<'_, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_escaped(formatter, format_args!("{}", self.0))
    }
}

impl<T: fmt::Display + ?Sized> fmt::Debug for EscapedLogPath<'_, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

/// A non-path value that is safe to render into a single-line tracing field.
///
/// Secrets use dedicated types that intentionally do not implement `Display`,
/// so they cannot be passed here without an explicit plaintext exposure at the
/// call site. This type itself exposes no access to its wrapped value.
#[must_use]
pub(crate) struct EscapedLogValue<'a, T: ?Sized>(&'a T);

impl<'a, T: ?Sized> EscapedLogValue<'a, T> {
    pub(crate) fn new(value: &'a T) -> Self {
        Self(value)
    }
}

impl<T: fmt::Display + ?Sized> fmt::Display for EscapedLogValue<'_, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_escaped(formatter, format_args!("{}", self.0))
    }
}

impl<T: fmt::Display + ?Sized> fmt::Debug for EscapedLogValue<'_, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

fn write_escaped(formatter: &mut fmt::Formatter<'_>, arguments: fmt::Arguments<'_>) -> fmt::Result {
    fmt::write(&mut EscapingWriter(formatter), arguments)
}

struct EscapingWriter<'a, 'b>(&'a mut fmt::Formatter<'b>);

impl fmt::Write for EscapingWriter<'_, '_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        for character in value.chars() {
            if character.is_control() || matches!(character, '\u{2028}' | '\u{2029}') {
                for escaped in character.escape_default() {
                    self.0.write_char(escaped)?;
                }
            } else {
                self.0.write_char(character)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_line_injection_characters_are_escaped() {
        let value = EscapedLogValue::new("first\r\nsecond\tfield");

        assert_eq!(value.to_string(), "first\\r\\nsecond\\tfield");
        assert_eq!(format!("{value:?}"), "first\\r\\nsecond\\tfield");
    }

    #[test]
    fn every_c0_c1_and_delete_control_is_removed_from_output() {
        let input = (0_u32..=0x9f)
            .chain(std::iter::once(0x7f))
            .filter_map(char::from_u32)
            .collect::<String>();
        let output = EscapedLogValue::new(&input).to_string();

        assert!(!output.chars().any(char::is_control));
        assert!(output.contains("\\u{0}"));
        assert!(output.contains("\\u{1f}"));
        assert!(output.contains("\\u{7f}"));
        assert!(output.contains("\\u{85}"));
        assert!(output.contains("\\u{9f}"));
    }

    #[test]
    fn unicode_text_is_preserved_but_unicode_line_separators_are_escaped() {
        let input = "Grüße 東京 🗝️\u{2028}next\u{2029}paragraph";
        let output = EscapedLogPath::new(input).to_string();

        assert_eq!(output, "Grüße 東京 🗝️\\u{2028}next\\u{2029}paragraph");
        assert!(!output.contains('\u{2028}'));
        assert!(!output.contains('\u{2029}'));
    }

    #[test]
    fn wrappers_do_not_expose_a_raw_value_through_debug() {
        let raw = "safe-prefix\nforged-event";
        let value = EscapedLogValue::new(raw);
        let path = EscapedLogPath::new(raw);

        assert_eq!(format!("{value:?}"), "safe-prefix\\nforged-event");
        assert_eq!(format!("{path:?}"), "safe-prefix\\nforged-event");
        assert!(!format!("{value:?}").contains('\n'));
        assert!(!format!("{path:?}").contains('\n'));
    }
}
