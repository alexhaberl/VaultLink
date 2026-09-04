use std::{
    io::{self, Read as _},
    pin::Pin,
    task::{Context, Poll},
};

#[cfg(test)]
use std::sync::{Arc, OnceLock};

use bytes::Bytes;
use futures_util::Stream;

use crate::{
    policy::{self, PreviewKind},
    runtime::RuntimeSettings,
    secure_fs::SecureFile,
};

use super::zip::DirectoryAccess;

const TEXT_PREVIEW_STREAM_MARKER: &str = "<!--VAULTLINK_ESCAPED_TEXT_PREVIEW_STREAM-->";
const MAX_RENDERED_TEXT_PREVIEW_BYTES: usize = crate::config::MAX_TEXT_PREVIEW_SIZE as usize;

pub(crate) enum PreviewContent {
    TooLarge { size: u64 },
    Text(String),
    Media { kind: PreviewKind, size: u64 },
}

#[cfg(test)]
pub(crate) struct TextPreviewReadTestHook {
    pub(crate) path: String,
    pub(crate) entered: std::sync::atomic::AtomicUsize,
    pub(crate) released: std::sync::Mutex<bool>,
    pub(crate) wake: std::sync::Condvar,
}

#[cfg(test)]
impl TextPreviewReadTestHook {
    pub(crate) fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }
}

#[cfg(test)]
pub(crate) struct TextPreviewReadTestGuard(pub(crate) Arc<TextPreviewReadTestHook>);

#[cfg(test)]
impl Drop for TextPreviewReadTestGuard {
    fn drop(&mut self) {
        self.0.release();
        let mut slot = TEXT_PREVIEW_READ_TEST_HOOK
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .unwrap();
        if slot
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, &self.0))
        {
            *slot = None;
        }
    }
}

#[cfg(test)]
pub(crate) static TEXT_PREVIEW_READ_TEST_HOOK: OnceLock<
    std::sync::Mutex<Option<Arc<TextPreviewReadTestHook>>>,
> = OnceLock::new();

#[cfg(test)]
fn block_text_preview_read_for_test(path: &str) {
    use std::sync::atomic::Ordering;

    let hook = TEXT_PREVIEW_READ_TEST_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap()
        .clone();
    let Some(hook) = hook.filter(|hook| hook.path == path) else {
        return;
    };
    hook.entered.fetch_add(1, Ordering::AcqRel);
    let mut released = hook.released.lock().unwrap();
    while !*released {
        released = hook.wake.wait(released).unwrap();
    }
}

pub(crate) struct EscapedTextPageStream {
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
                        .saturating_add(super::BUFFERED_RESPONSE_CHUNK_BYTES)
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
                    let mut chunk = String::with_capacity(super::BUFFERED_RESPONSE_CHUNK_BYTES);
                    while this.text_offset < this.text.len() {
                        let character = this.text[this.text_offset..]
                            .chars()
                            .next()
                            .expect("text offset is a UTF-8 boundary");
                        let length = escaped_character_len(character);
                        if !chunk.is_empty()
                            && chunk.len().saturating_add(length)
                                > super::BUFFERED_RESPONSE_CHUNK_BYTES
                        {
                            break;
                        }
                        if length > this.escaped_remaining {
                            this.phase = 3;
                            return Poll::Ready(Some(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "escaped preview exceeds its output cap",
                            ))));
                        }
                        push_html_escaped(&mut chunk, character);
                        this.text_offset += character.len_utf8();
                        this.escaped_remaining -= length;
                    }
                    return Poll::Ready(Some(Ok(Bytes::from(chunk))));
                }
                2 => {
                    if this.suffix_offset >= this.page.len() {
                        this.phase = 3;
                        continue;
                    }
                    let end = this
                        .suffix_offset
                        .saturating_add(super::BUFFERED_RESPONSE_CHUNK_BYTES)
                        .min(this.page.len());
                    let chunk = this.page.slice(this.suffix_offset..end);
                    this.suffix_offset = end;
                    return Poll::Ready(Some(Ok(chunk)));
                }
                _ => return Poll::Ready(None),
            }
        }
    }
}

pub(crate) fn escaped_text_page_stream(
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
    Ok((
        EscapedTextPageStream {
            page: Bytes::from(page_template),
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

pub(crate) fn escaped_html_len(value: &str) -> Option<usize> {
    value.chars().try_fold(0usize, |length, character| {
        length.checked_add(escaped_character_len(character))
    })
}

fn escaped_character_len(character: char) -> usize {
    match character {
        '&' => 5,
        '<' | '>' => 4,
        '"' => 6,
        '\'' => 5,
        character => character.len_utf8(),
    }
}

fn push_html_escaped(escaped: &mut String, character: char) {
    match character {
        '&' => escaped.push_str("&amp;"),
        '<' => escaped.push_str("&lt;"),
        '>' => escaped.push_str("&gt;"),
        '"' => escaped.push_str("&quot;"),
        '\'' => escaped.push_str("&#39;"),
        character => escaped.push(character),
    }
}

pub(crate) fn read_preview<D: DirectoryAccess>(
    directory: &D,
    path: &str,
    settings: &RuntimeSettings,
) -> io::Result<PreviewContent> {
    let metadata = directory.entry_metadata(path)?;
    let file = directory.open_regular_file(path)?;
    read_preview_opened(file, &metadata, path, settings)
}

pub(crate) fn read_preview_secure_file(
    file: SecureFile,
    path: &str,
    settings: &RuntimeSettings,
) -> io::Result<PreviewContent> {
    let metadata = file.metadata()?;
    read_preview_opened(file.into_file(), &metadata, path, settings)
}

pub(crate) fn read_preview_opened(
    file: std::fs::File,
    metadata: &std::fs::Metadata,
    path: &str,
    settings: &RuntimeSettings,
) -> io::Result<PreviewContent> {
    let kind = policy::preview_kind(path, settings).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "preview extension is not allowed",
        )
    })?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "preview target is not a file",
        ));
    }
    if kind.is_media() {
        return if metadata.len() > settings.max_media_preview_size {
            Ok(PreviewContent::TooLarge {
                size: metadata.len(),
            })
        } else {
            Ok(PreviewContent::Media {
                kind,
                size: metadata.len(),
            })
        };
    }
    if metadata.len() > settings.max_preview_size {
        return Ok(PreviewContent::TooLarge {
            size: metadata.len(),
        });
    }
    #[cfg(test)]
    block_text_preview_read_for_test(path);
    read_text_preview(file, metadata.len(), settings.max_preview_size)
}

fn read_text_preview(
    file: std::fs::File,
    metadata_len: u64,
    maximum: u64,
) -> io::Result<PreviewContent> {
    let read_limit = maximum.checked_add(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "preview size limit is too large",
        )
    })?;
    let allocation = usize::try_from(read_limit).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "preview size does not fit in memory",
        )
    })?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(allocation)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let mut file = file.take(read_limit);
    let mut buffer = [0_u8; super::BUFFERED_RESPONSE_CHUNK_BYTES];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    if bytes.len() as u64 > maximum {
        return Ok(PreviewContent::TooLarge {
            size: metadata_len.max(bytes.len() as u64),
        });
    }
    if bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "binary content is not previewed",
        ));
    }
    String::from_utf8(bytes)
        .map(PreviewContent::Text)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "text preview is not valid UTF-8",
            )
        })
}
