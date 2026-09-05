//! Bounded fixtures for the real ZIP writer, preview reader and HTML stream.

use std::{
    fs::File,
    io::{self, Seek, Write},
    path::PathBuf,
    pin::Pin,
    task::{Context, Poll},
};

use futures_util::{task::noop_waker_ref, Stream};

use super::{preview, zip};
use crate::{runtime::RuntimeSettings, secure_fs::DirectoryScan};

const MAX_INPUT_BYTES: usize = 16 * 1024;
const PREVIEW_MARKER: &str = "<!--VAULTLINK_ESCAPED_TEXT_PREVIEW_STREAM-->";

/// Raw bytes select up to four archive entries, source/plan size disagreement,
/// output limits, stale preview metadata and text/HTML content. No fixture path
/// is derived from input; all reads and writes stay in a fresh temporary folder.
pub fn check_zip_preview(input: &[u8]) {
    let input = &input[..input.len().min(MAX_INPUT_BYTES)];
    let control = |index| input.get(index).copied().unwrap_or(0);
    let payload = input.get(8..).unwrap_or_default();
    check_zip(payload, [control(0), control(1), control(2), control(3)]);
    check_preview_read(payload, control(4), control(5));
    check_preview_stream(payload, control(6));
}

#[derive(Clone)]
struct FixtureDirectory(PathBuf);

impl zip::DirectoryAccess for FixtureDirectory {
    fn scan_entries(&self, _relative: &str) -> io::Result<DirectoryScan> {
        // The writer consumes an already-built, bounded plan. This fixture
        // targets serialization and source-size changes without a tree scan.
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "fixture has no scanner",
        ))
    }

    fn open_regular_file(&self, relative: &str) -> io::Result<File> {
        File::open(self.0.join(relative))
    }

    fn entry_metadata(&self, relative: &str) -> io::Result<std::fs::Metadata> {
        std::fs::metadata(self.0.join(relative))
    }
}

struct ExpectedEntry {
    name: String,
    bytes: Vec<u8>,
    is_directory: bool,
}

fn check_zip(payload: &[u8], control: [u8; 4]) {
    let temporary = tempfile::tempdir().unwrap();
    let directory = FixtureDirectory(temporary.path().to_owned());
    let count = usize::from(control[0] % 5);
    let mut files = Vec::new();
    let mut expected = Vec::new();
    for index in 0..count {
        let bytes = &payload[payload.len() * index / count..payload.len() * (index + 1) / count];
        let is_directory = control[1] & (1 << index) != 0;
        let suffix = String::from_utf8_lossy(&bytes[..bytes.len().min(24)])
            .chars()
            .filter(|character| !character.is_control() && !matches!(*character, '/' | '\\'))
            .collect::<String>();
        let name = format!(
            "entry-{index}-{suffix}{}",
            if is_directory { "/" } else { ".txt" }
        );
        let source_path = format!("source-{index}");
        let scanned_len = if is_directory {
            0
        } else {
            match (control[2] >> (index * 2)) & 3 {
                0 => bytes.len(),
                1 => bytes.len() / 2,
                2 => bytes.len() + 17,
                _ => 0,
            }
        };
        if !is_directory {
            std::fs::write(temporary.path().join(&source_path), bytes).unwrap();
        }
        expected.push(ExpectedEntry {
            name: name.clone(),
            bytes: if is_directory {
                Vec::new()
            } else {
                bytes[..bytes.len().min(scanned_len)].to_vec()
            },
            is_directory,
        });
        files.push(zip::ZipFilePlan {
            source_path: source_path.into(),
            archive_name: name.into(),
            scanned_len: scanned_len as u64,
            is_directory,
        });
    }
    let actual_bytes = expected
        .iter()
        .map(|entry| entry.bytes.len() as u64)
        .sum::<u64>();
    let maximum = match control[3] % 3 {
        0 => 0,
        1 => actual_bytes,
        _ => actual_bytes.saturating_sub(1),
    };
    let plan = zip::ZipPlan {
        estimated_archive_size: zip::estimate_zip_archive_size(&files).unwrap(),
        files,
        max_data_size: maximum,
    };
    let archive = zip::write_zip_archive(&directory, &plan, Vec::new());
    if maximum != 0 && actual_bytes > maximum {
        assert!(matches!(archive, Err(zip::ZipBuildError::Limit(_))));
        return;
    }
    let archive = archive.unwrap();
    assert!(archive.len() as u64 <= plan.estimated_archive_size);
    verify_archive(&archive, &expected);
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

// A deliberately independent, bitwise IEEE CRC-32 oracle; production uses
// crc32fast. This checks data and checksum instead of merely matching headers.
fn reference_crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 == 0 { 0 } else { 0xedb8_8320 };
        }
    }
    !crc
}

fn zip64_extra(extra: &[u8]) -> &[u8] {
    let mut offset = 0;
    while offset < extra.len() {
        let kind = u16_at(extra, offset);
        let length = usize::from(u16_at(extra, offset + 2));
        let payload = &extra[offset + 4..offset + 4 + length];
        if kind == 1 {
            return payload;
        }
        offset += 4 + length;
    }
    panic!("missing ZIP64 extra field");
}

// Read central-directory and local records independently using their declared
// lengths and offsets. Input never supplies an archive or allocation size here:
// only the small archive emitted by VaultLink is decoded by this test oracle.
fn verify_archive(archive: &[u8], expected: &[ExpectedEntry]) {
    assert!(archive.len() >= 98);
    let end = archive.len() - 22;
    assert_eq!(u32_at(archive, end), 0x0605_4b50);
    assert_eq!(u16_at(archive, end + 20), 0);
    let locator = end - 20;
    assert_eq!(u32_at(archive, locator), 0x0706_4b50);
    assert_eq!(u32_at(archive, locator + 16), 1);
    let zip64_end = usize::try_from(u64_at(archive, locator + 8)).unwrap();
    assert_eq!(zip64_end + 56, locator);
    assert_eq!(u32_at(archive, zip64_end), 0x0606_4b50);
    assert_eq!(u64_at(archive, zip64_end + 24), expected.len() as u64);
    assert_eq!(u64_at(archive, zip64_end + 32), expected.len() as u64);
    let central_size = usize::try_from(u64_at(archive, zip64_end + 40)).unwrap();
    let central_start = usize::try_from(u64_at(archive, zip64_end + 48)).unwrap();
    assert_eq!(central_start + central_size, zip64_end);

    let mut central = central_start;
    let mut next_local = 0;
    for entry in expected {
        (central, next_local) = verify_archive_entry(archive, entry, central, next_local);
    }
    assert_eq!(next_local, central_start);
    assert_eq!(central, zip64_end);
}

fn verify_archive_entry(
    archive: &[u8],
    entry: &ExpectedEntry,
    central: usize,
    next_local: usize,
) -> (usize, usize) {
    assert_eq!(u32_at(archive, central), 0x0201_4b50);
    assert_eq!(u16_at(archive, central + 10), 0, "stored compression");
    let name_len = usize::from(u16_at(archive, central + 28));
    let extra_len = usize::from(u16_at(archive, central + 30));
    let comment_len = usize::from(u16_at(archive, central + 32));
    assert_eq!(
        &archive[central + 46..central + 46 + name_len],
        entry.name.as_bytes()
    );
    let extra = zip64_extra(&archive[central + 46 + name_len..central + 46 + name_len + extra_len]);
    assert_eq!(u64_at(extra, 0), entry.bytes.len() as u64);
    assert_eq!(u64_at(extra, 8), entry.bytes.len() as u64);
    let local = usize::try_from(u64_at(extra, 16)).unwrap();
    assert_eq!(local, next_local);
    let crc = reference_crc32(&entry.bytes);
    assert_eq!(u32_at(archive, central + 16), crc);
    assert_eq!(
        u32_at(archive, central + 38) & 0x10 != 0,
        entry.is_directory
    );
    assert_eq!(u32_at(archive, local), 0x0403_4b50);
    assert_eq!(u16_at(archive, local + 8), 0);
    assert_eq!(u16_at(archive, local + 6) & 0x0808, 0x0808);
    let local_name_len = usize::from(u16_at(archive, local + 26));
    let local_extra_len = usize::from(u16_at(archive, local + 28));
    assert_eq!(
        &archive[local + 30..local + 30 + local_name_len],
        entry.name.as_bytes()
    );
    let content = local + 30 + local_name_len + local_extra_len;
    assert_eq!(
        &archive[content..content + entry.bytes.len()],
        entry.bytes.as_slice()
    );
    let descriptor = content + entry.bytes.len();
    assert_eq!(u32_at(archive, descriptor), 0x0807_4b50);
    assert_eq!(u32_at(archive, descriptor + 4), crc);
    assert_eq!(u64_at(archive, descriptor + 8), entry.bytes.len() as u64);
    assert_eq!(u64_at(archive, descriptor + 16), entry.bytes.len() as u64);
    (
        central + 46 + name_len + extra_len + comment_len,
        descriptor + 24,
    )
}

fn preview_settings(maximum: u64) -> RuntimeSettings {
    RuntimeSettings {
        public_base_url: "http://localhost".into(),
        max_upload_size: 1,
        blocked_extensions: Vec::new(),
        share_password_min_length: 8,
        share_password_max_length: 128,
        share_unlock_minutes: 1,
        max_zip_size: 1,
        max_zip_files: 1,
        max_search_entries: 1,
        max_search_results: 1,
        max_preview_size: maximum,
        preview_extensions: vec!["txt".into()],
        image_preview_extensions: vec!["png".into()],
        pdf_preview_enabled: true,
        max_media_preview_size: maximum,
        audit_client_ip_enabled: false,
    }
}

fn check_preview_read(payload: &[u8], length_control: u8, limit_control: u8) {
    let mut file = tempfile::tempfile().unwrap();
    let initial_len = match length_control % 3 {
        0 => payload.len(),
        1 => payload.len() / 2,
        _ => payload.len() + 17,
    };
    file.set_len(initial_len as u64).unwrap();
    let metadata = file.metadata().unwrap();
    file.set_len(0).unwrap();
    file.write_all(payload).unwrap();
    file.rewind().unwrap();
    let maximum = match limit_control % 4 {
        0 => payload.len(),
        1 => payload.len().saturating_sub(1),
        2 => payload.len() + 1,
        _ => usize::from(limit_control) % (payload.len() + 1),
    } as u64;
    let result =
        preview::read_preview_opened(file, &metadata, "fixture.txt", &preview_settings(maximum));
    if initial_len as u64 > maximum || payload.len() as u64 > maximum {
        let preview::PreviewContent::TooLarge { size } = result.unwrap() else {
            panic!("over-limit input must not produce a truncated text preview");
        };
        let expected_size = if initial_len as u64 > maximum {
            initial_len as u64
        } else {
            maximum + 1
        };
        assert_eq!(size, expected_size);
    } else if !payload.contains(&0) && std::str::from_utf8(payload).is_ok() {
        let preview::PreviewContent::Text(actual) = result.unwrap() else {
            panic!("bounded UTF-8 input must produce its complete text");
        };
        assert_eq!(actual.as_bytes(), payload);
    } else {
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidData));
    }
}

fn check_preview_stream(payload: &[u8], repetition_control: u8) {
    // Repetition exercises UTF-8/entity boundaries across output chunks while
    // keeping the largest raw text below 256 KiB.
    let text = String::from_utf8_lossy(payload).repeat(1 + usize::from(repetition_control % 4));
    let expected = text
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;");
    assert_eq!(preview::escaped_html_len(&text), Some(expected.len()));
    assert!(preview::escaped_text_page_stream("no marker".into(), text.clone()).is_err());
    assert!(preview::escaped_text_page_stream(
        format!("{PREVIEW_MARKER}{PREVIEW_MARKER}"),
        text.clone()
    )
    .is_err());
    let (mut stream, declared_length) =
        preview::escaped_text_page_stream(format!("<pre>{PREVIEW_MARKER}</pre>"), text).unwrap();
    let mut output = Vec::new();
    let mut context = Context::from_waker(noop_waker_ref());
    for _ in 0..64 {
        match Pin::new(&mut stream).poll_next(&mut context) {
            Poll::Ready(Some(Ok(chunk))) => {
                assert!(chunk.len() <= super::BUFFERED_RESPONSE_CHUNK_BYTES);
                output.extend_from_slice(&chunk);
                assert!(output.len() as u64 <= declared_length);
            }
            Poll::Ready(None) => {
                assert_eq!(output.len() as u64, declared_length);
                assert_eq!(output, format!("<pre>{expected}</pre>").as_bytes());
                assert!(matches!(
                    Pin::new(&mut stream).poll_next(&mut context),
                    Poll::Ready(None)
                ));
                return;
            }
            other => panic!("bounded in-memory preview stream failed: {other:?}"),
        }
    }
    panic!("preview stream exceeded its bounded number of chunks");
}

#[cfg(test)]
mod tests {
    #[test]
    fn curated_zip_preview_seeds() {
        for seed in [
            include_bytes!("../../fuzz/corpus/zip_preview/empty").as_slice(),
            include_bytes!("../../fuzz/corpus/zip_preview/stored_utf8_directory"),
            include_bytes!("../../fuzz/corpus/zip_preview/source_shorter_than_plan"),
            include_bytes!("../../fuzz/corpus/zip_preview/source_longer_than_plan"),
            include_bytes!("../../fuzz/corpus/zip_preview/empty_planned_content"),
            include_bytes!("../../fuzz/corpus/zip_preview/aggregate_size_limit"),
            include_bytes!("../../fuzz/corpus/zip_preview/invalid_utf8"),
            include_bytes!("../../fuzz/corpus/zip_preview/binary_text"),
            include_bytes!("../../fuzz/corpus/zip_preview/preview_grew"),
            include_bytes!("../../fuzz/corpus/zip_preview/escaped_chunk_boundary"),
        ] {
            super::check_zip_preview(seed);
        }
    }
}
