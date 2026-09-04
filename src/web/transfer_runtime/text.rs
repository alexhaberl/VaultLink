pub(super) struct EscapedTextPageStream {
    page: Bytes,
    prefix_end: usize,
    prefix_offset: usize,
    suffix_offset: usize,
    text: String,
    text_offset: usize,
    escaped_remaining: usize,
    phase: u8,
}

impl Stream for EscapedTextPageStream {
    type Item = io::Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            match this.phase {
                0 => {
                    if this.prefix_offset >= this.prefix_end {
                        this.phase = 1;
                        continue;
                    }
                    let end = this
                        .prefix_offset
                        .saturating_add(BUFFERED_RESPONSE_CHUNK_BYTES)
                        .min(this.prefix_end);
                    let chunk = this.page.slice(this.prefix_offset..end);
                    this.prefix_offset = end;
                    return Poll::Ready(Some(Ok(chunk)));
                }
                1 => {
                    if this.text_offset >= this.text.len() {
                        if this.escaped_remaining != 0 {
                            this.phase = 3;
                            return Poll::Ready(Some(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "escaped preview length mismatch",
                            ))));
                        }
                        this.phase = 2;
                        continue;
                    }
                    let mut chunk = String::with_capacity(BUFFERED_RESPONSE_CHUNK_BYTES);
                    while this.text_offset < this.text.len() {
                        let character = this.text[this.text_offset..]
                            .chars()
                            .next()
                            .expect("text offset is a UTF-8 boundary");
                        let escaped_length = match character {
                            '&' => 5,
                            '<' | '>' => 4,
                            '"' => 6,
                            '\'' => 5,
                            character => character.len_utf8(),
                        };
                        if !chunk.is_empty()
                            && chunk.len().saturating_add(escaped_length)
                                > BUFFERED_RESPONSE_CHUNK_BYTES
                        {
                            break;
                        }
                        if escaped_length > this.escaped_remaining {
                            this.phase = 3;
                            return Poll::Ready(Some(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "escaped preview exceeds its output cap",
                            ))));
                        }
                        push_html_escaped(&mut chunk, character);
                        this.text_offset += character.len_utf8();
                        this.escaped_remaining -= escaped_length;
                    }
                    return Poll::Ready(Some(Ok(Bytes::from(chunk))));
                }
                2 => {
                    let suffix_end = this.page.len();
                    if this.suffix_offset >= suffix_end {
                        this.phase = 3;
                        continue;
                    }
                    let end = this
                        .suffix_offset
                        .saturating_add(BUFFERED_RESPONSE_CHUNK_BYTES)
                        .min(suffix_end);
                    let chunk = this.page.slice(this.suffix_offset..end);
                    this.suffix_offset = end;
                    return Poll::Ready(Some(Ok(chunk)));
                }
                _ => return Poll::Ready(None),
            }
        }
    }
}

/// Inserts a text preview into the single marker emitted by an Askama shell.
///
/// This is the one deliberate exception to Askama's normal value rendering:
/// preview text can be large, so it is HTML-escaped incrementally under the
/// rendered-output cap instead of first allocating a second escaped string.
pub(super) fn escaped_text_page_stream(
    page_template: String,
    text: String,
) -> io::Result<(EscapedTextPageStream, u64)> {
    let marker_index = page_template
        .find(TEXT_PREVIEW_STREAM_MARKER)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "preview marker is missing"))?;
    let suffix_start = marker_index + TEXT_PREVIEW_STREAM_MARKER.len();
    if page_template[suffix_start..].contains(TEXT_PREVIEW_STREAM_MARKER) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "preview marker is ambiguous",
        ));
    }
    let escaped_length = escaped_html_len(&text)
        .filter(|length| *length <= MAX_RENDERED_TEXT_PREVIEW_BYTES)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "escaped preview exceeds its output cap",
            )
        })?;
    let page_length = marker_index
        .checked_add(escaped_length)
        .and_then(|length| length.checked_add(page_template.len() - suffix_start))
        .and_then(|length| u64::try_from(length).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "preview size overflow"))?;
    let page = Bytes::from(page_template);
    Ok((
        EscapedTextPageStream {
            page,
            prefix_end: marker_index,
            prefix_offset: 0,
            suffix_offset: suffix_start,
            text,
            text_offset: 0,
            escaped_remaining: escaped_length,
            phase: 0,
        },
        page_length,
    ))
}
