#!/usr/bin/env python3
"""Build curated cargo-fuzz seeds; optionally verify the real Rust decoder offline.

arbitrary 1.4 stores String lengths at the *end* of the remaining input,
integer values little-endian, length selectors big-endian, and Vec elements
behind boolean continuation bytes. JSON or plain text is not a tuple seed.
Run --check --verify-rust to compare tracked seeds and prove every tuple decodes
to its intended value using the locally cached arbitrary crate and rustc.
"""

import argparse
import os
from pathlib import Path
import struct
import subprocess


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "fuzz" / "corpus"
SCHEMAS = {
    "path_normalization": ("str",),
    "filename": ("str",),
    "byte_range": ("str", "u64"),
    "zip_search_preview_paths": ("str", "str", "str"),
    "upload_overwrite_policy": ("str", "str", "str", "bool", "u8"),
    "file_mutation_policy": ("str", "str", "str", "str", "option_str", "bool"),
    "share_request_policy": ("str", "str", "str", "u8", "bool", "bool", "u8", "u8", "str"),
    "upload_request_state": ("vec_u8", "u8", "str", "str", "str", "vec_u64", "u64", "u64"),
}


def prepend(kind, value, rest, take_rest=False):
    if kind == "str":
        raw = value.encode("utf-8")
        if take_rest:
            return raw
        payload = raw + rest
        width = next(n for n in (1, 2, 4, 8) if len(payload) <= (1 << (8 * n)) - 1)
        return payload + len(raw).to_bytes(width, "big")
    if kind == "option_str":
        return b"\x00" + rest if value is None else b"\x01" + prepend("str", value, rest)
    if kind.startswith("vec_"):
        element = kind.removeprefix("vec_")
        output = b"\x00" + rest
        for item in reversed(value):
            output = b"\x01" + prepend(element, item, output)
        return output
    width = 1 if kind == "bool" else int(kind[1:]) // 8
    return int(value).to_bytes(width, "little") + rest


def encode(schema, values):
    result = b""
    for index in reversed(range(len(schema))):
        result = prepend(schema[index], values[index], result, index == len(schema) - 1)
    return result


def multipart(mode, payload=b"payload", preamble=64, header=128, eof=0, chunk=0, boundary=b"\0"):
    assert 1 <= len(boundary) <= 70
    return struct.pack("<BHHIBB", mode, preamble, header, eof, chunk, len(boundary) - 1) + boundary + payload


def seeds():
    cases = []

    def add(target, name, *values):
        schema = SCHEMAS[target]
        cases.append((target, name, encode(schema, values), values))

    for name, value in {
        "normal": "docs/Grüße.txt", "traversal": "../private", "encoded_literal": "%2e%2e/file",
        "private_namespace": "docs/.VaUlTlInK-InTeRnAl /uploads", "backslash": "a\\..\\b", "null_byte": "a\0b",
    }.items():
        add("path_normalization", name, value)
    for name, value in {
        "normal": "Grüße.txt", "windows_reserved": "CON.txt", "trailing_dot": "file.",
        "private_fragment": ".vaultlink-abcdefghijklmnopqrstuvwx.part", "max_bytes": "x" * 255,
        "over_bytes": "x" * 256, "private_namespace": ".VAULTLINK-INTERNAL",
    }.items():
        add("filename", name, value)
    for name, value, length in [
        ("closed", "bytes=0-9", 100), ("suffix", "bytes=-10", 100), ("open", "bytes=90-", 100),
        ("empty", "bytes=0-0", 0), ("multi", "bytes=0-1,3-4", 100),
        ("overflow", "bytes=18446744073709551616-", (1 << 64) - 1),
        ("u64_end", "bytes=18446744073709551614-", (1 << 64) - 1),
    ]:
        add("byte_range", name, value, length)
    for name, base, child, extensions in [
        ("normal", "docs", "report.txt", ".TXT,pdf;PNG"),
        ("traversal", "share", "../sibling", "txt"),
        ("private", "share", ".vaultlink-internal/uploads", "txt"),
        ("bad_extensions", "", "100%.txt", "txt,../exe"),
    ]:
        add("zip_search_preview_paths", name, base, child, extensions)
    for name, directory, filename, checkbox, strategy in [
        ("replace", "nested", "file.txt", "1", True),
        ("reject_policy", "", "file.txt", "1", False),
        ("reject_checkbox", "", "file.txt", "on", True),
        ("private_destination", "", ".vaultlink-abcdefghijklmnopqrstuvwx.part", "1", True),
        ("traversal", "../outside", "file.txt", "1", True),
    ]:
        add("upload_overwrite_policy", name, directory, filename, checkbox, strategy, 42)
    for name, values in {
        "rename_nested": ("docs/old", "new", "docs/old/file.txt", "docs/new", "old", True),
        "prefix_collision": ("docs/old", "new", "docs/older/file.txt", "docs/new", "wrong", True),
        "private_destination": ("docs/old", ".vaultlink-abcdefghijklmnopqrstuvwx.part", "docs/old", "docs/new", None, False),
        "root": ("", "new", "", "new", None, True),
    }.items():
        add("file_mutation_policy", name, *values)
    for name, values in {
        "directory_overwrite": ("docs", "alias-123456789", "long-password", 2, True, True, 8, 32, "txt,pdf"),
        "upload_file_rejected": ("file.txt", "alias-123456789", "12345678", 1, False, False, 8, 0, "txt"),
        "short_password": ("docs", "short", "1234567", 0, True, False, 8, 0, "txt"),
        "unicode_password": ("docs", "alias_123456789", "🔒" * 64, 2, True, True, 8, 100, "TXT"),
    }.items():
        add("share_request_policy", name, *values)
    for name, fields, chunks, maximum, initial in [
        ("folder_valid", [0, 5, 2, 3, 1], [4, 6], 10, 0),
        ("folder_duplicate", [5, 5, 3], [0], 0, 0),
        ("folder_late", [3, 5], [1], 10, 0),
        ("all_duplicates", [0, 0, 2, 2, 3, 3, 1, 1], [11], 10, 0),
        ("field_limit", [4] * 9, [0], 1, 0),
        ("byte_overflow", [5, 3], [1, 0], (1 << 64) - 1, (1 << 64) - 1),
        ("already_too_large", [3], [0], 1, 2),
    ]:
        add("upload_request_state", name, fields, 2, "docs", "file.txt", "exe", chunks, maximum, initial)

    multipart_cases = {
        "valid_body": multipart(1), "header_bytes": multipart(2, b"X: y\r\nContent-Disposition: form-data; name=\"file\""),
        "preamble_bytes": multipart(3, b"preamble"), "raw_eof": multipart(0, b"--a\r\nX:"),
        "header_exact": multipart(4), "header_over": multipart(4 | 8),
        "preamble_exact": multipart(5), "preamble_over": multipart(5 | 8),
        "two_fields": multipart(6), "quoted_boundary": multipart(1 | 0x10, boundary=b"\0\0\1\0\1"),
        "long_boundary": multipart(1, boundary=b"\0" * 70),
        "late_eof": multipart(1 | 0x80, b"x" * 1024, eof=768),
        "content_type_duplicate": multipart(7, b"multipart/form-data; boundary=x; boundary=y"),
        "content_type_quoted": multipart(7, b'multipart/form-data; boundary="x"'),
        "content_type_invalid": multipart(7, b'multipart/form-data; boundary="unterminated'),
    }
    cases.extend(("multipart_guard", name, raw, None) for name, raw in multipart_cases.items())
    return cases


def rust_value(kind, value):
    if kind == "str":
        return "String::from_utf8(vec![" + ",".join(map(str, value.encode("utf-8"))) + "]).unwrap()"
    if kind == "option_str":
        return "None" if value is None else "Some(" + rust_value("str", value) + ")"
    if kind.startswith("vec_"):
        return "vec![" + ",".join(map(str, value)) + "]"
    if kind == "bool":
        return str(value).lower()
    return str(value)


def verify_rust(cases, arbitrary_source):
    source = arbitrary_source
    if source is None:
        cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
        candidates = sorted((cargo_home / "registry" / "src").glob("*/arbitrary-1.4.*/src/lib.rs"))
        if not candidates:
            raise SystemExit("arbitrary 1.4 source is not cached; supply --arbitrary-source (no download is performed)")
        source = candidates[-1]
    out = ROOT / "target" / "fuzz-seed-check"
    out.mkdir(parents=True, exist_ok=True)
    rlib = out / "libarbitrary.rlib"
    subprocess.run(["rustc", "--edition=2021", "--crate-name=arbitrary", "--crate-type=rlib", str(source), "-o", str(rlib)], check=True)
    aliases = {"str": "String", "option_str": "Option<String>", "vec_u8": "Vec<u8>", "vec_u64": "Vec<u64>"}
    lines = ["use arbitrary::{Arbitrary, Unstructured};", "fn main() {"]
    for target, name, _, values in cases:
        if values is None:
            continue
        schema = SCHEMAS[target]
        rust_type = ",".join(aliases.get(kind, kind) for kind in schema)
        expected = ",".join(rust_value(kind, value) for kind, value in zip(schema, values))
        if len(schema) > 1:
            rust_type, expected = f"({rust_type})", f"({expected})"
        path = (CORPUS / target / name).as_posix()
        lines.append(f'let raw = std::fs::read(r#"{path}"#).unwrap();')
        lines.append(f'let decoded = <{rust_type}>::arbitrary_take_rest(Unstructured::new(&raw)).unwrap();')
        lines.append(f'assert_eq!(decoded, {expected}, "{target}/{name}");')
    lines.append('println!("All typed seeds decode to their intended values"); }')
    decoder = out / "verify.rs"
    decoder.write_text("\n".join(lines), encoding="utf-8")
    executable = out / ("verify.exe" if os.name == "nt" else "verify")
    subprocess.run(["rustc", "--edition=2021", str(decoder), "--extern", f"arbitrary={rlib}", "-o", str(executable)], check=True)
    subprocess.run([str(executable)], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail on a missing or changed curated seed")
    parser.add_argument("--verify-rust", action="store_true", help="compile and run the real arbitrary decoder offline")
    parser.add_argument("--arbitrary-source", type=Path, help="path to arbitrary 1.4 src/lib.rs")
    args = parser.parse_args()
    cases = seeds()
    for target, name, raw, _ in cases:
        path = CORPUS / target / name
        if args.check:
            if not path.is_file() or path.read_bytes() != raw:
                raise SystemExit(f"seed differs: {path}")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
    print(f"{'Checked' if args.check else 'Generated'} {len(cases)} curated seeds across nine targets", flush=True)
    if args.verify_rust:
        verify_rust(cases, args.arbitrary_source)


if __name__ == "__main__":
    main()
