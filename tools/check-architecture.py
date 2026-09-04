#!/usr/bin/env python3
"""Fail-closed source architecture and physical-size policy for VaultLink."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
PRODUCTION_MODULE_MAX_LINES = 1_000
TEST_MODULE_MAX_LINES = 1_200
PRODUCTION_FUNCTION_MAX_LINES = 150
ALLOWLIST_MAX_LINES = 10_000

IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
FUNCTION = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)")
TEST_MODULE = re.compile(
    r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*"
    r"(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+[A-Za-z_][A-Za-z0-9_]*\s*\{",
    re.MULTILINE,
)
TEST_BRACED_ITEM = re.compile(
    r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*"
    r"(?:pub(?:\s*\([^)]*\))?\s+)?(?:unsafe\s+)?(?:impl|mod|trait)\b[^;{]*\{",
    re.MULTILINE,
)
TEST_USE = re.compile(
    r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*use\b.*?;",
    re.MULTILINE | re.DOTALL,
)
USE_STATEMENT = re.compile(r"\buse\b(?P<body>.*?);", re.DOTALL)
USE_TOKEN = re.compile(r"::|[A-Za-z_][A-Za-z0-9_]*|[{},*]")

TRANSPORT_CRATES = {
    "askama",
    "axum",
    "http",
    "http_body",
    "http_body_util",
    "hyper",
    "tower",
}

STATE_BORROW_BOUNDARIES = {
    "src/api/common.rs",
    "src/web/templates.rs",
}

# These permits are transport-neutral admission capabilities temporarily
# re-exported by `http_auth`. No service may depend on any other HTTP-auth item.
SERVICE_HTTP_AUTH_PERMITS = {"ClientActivityPermit", "ShareActivityPermit"}


@dataclass(frozen=True, order=True)
class Violation:
    path: str
    line: int
    code: str
    message: str


@dataclass(frozen=True)
class DataFileAllowance:
    path: str
    max_lines: int
    reason: str


class DuplicateKeyError(ValueError):
    pass


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def blank(chars: list[str], start: int, end: int) -> None:
    for index in range(start, end):
        if chars[index] not in "\r\n":
            chars[index] = " "


def scrub_rust(source: str) -> str:
    """Remove comments and literals while retaining offsets and newlines."""

    chars = list(source)
    index = 0
    length = len(source)
    while index < length:
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            if end == -1:
                end = length
            blank(chars, index, end)
            index = end
            continue

        if source.startswith("/*", index):
            depth = 1
            end = index + 2
            while end < length and depth > 0:
                if source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            blank(chars, index, end)
            index = end
            continue

        raw = re.match(r"(?:br|r)(?P<hashes>#{0,255})\"", source[index:])
        if raw is not None:
            delimiter = '"' + raw.group("hashes")
            content_start = index + raw.end()
            finish = source.find(delimiter, content_start)
            end = length if finish == -1 else finish + len(delimiter)
            blank(chars, index, end)
            index = end
            continue

        if source[index] == '"':
            end = index + 1
            while end < length:
                if source[end] == "\\":
                    end += 2
                    continue
                end += 1
                if source[end - 1] == '"':
                    break
            blank(chars, index, min(end, length))
            index = min(end, length)
            continue

        if source[index] == "'":
            character = re.match(r"'(?:\\.|[^\\'\r\n])'", source[index:])
            if character is not None:
                end = index + character.end()
                blank(chars, index, end)
                index = end
                continue

        index += 1
    return "".join(chars)


def matching_brace(source: str, opening: int) -> int | None:
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def test_spans(scrubbed: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = [match.span() for match in TEST_USE.finditer(scrubbed)]
    for match in list(TEST_MODULE.finditer(scrubbed)) + list(
        TEST_BRACED_ITEM.finditer(scrubbed)
    ):
        opening = scrubbed.rfind("{", match.start(), match.end())
        closing = matching_brace(scrubbed, opening)
        spans.append((match.start(), len(scrubbed) if closing is None else closing + 1))
    for match in FUNCTION.finditer(scrubbed):
        if not has_test_attribute(scrubbed, match.start()):
            continue
        opening = function_body_start(scrubbed, match.end())
        if opening is None:
            continue
        closing = matching_brace(scrubbed, opening)
        spans.append((match.start(), len(scrubbed) if closing is None else closing + 1))
    return spans


def in_spans(offset: int, spans: list[tuple[int, int]]) -> bool:
    return any(start <= offset < end for start, end in spans)


def has_test_attribute(scrubbed: str, function_offset: int) -> bool:
    line_start = scrubbed.rfind("\n", 0, function_offset) + 1
    prefix_start = line_start
    for _ in range(8):
        previous_end = max(0, prefix_start - 1)
        previous_start = scrubbed.rfind("\n", 0, previous_end) + 1
        previous = scrubbed[previous_start:previous_end].strip()
        if not previous or previous.startswith("#") or previous.endswith("]"):
            prefix_start = previous_start
            continue
        break
    attributes = scrubbed[prefix_start:function_offset]
    return bool(
        re.search(
            r"#\s*\[\s*(?:test\s*|tokio\s*::\s*test(?:\s*\([^\]]*\))?\s*|"
            r"cfg\s*\(\s*test\s*\)\s*)\]",
            attributes,
        )
    )


def function_body_start(scrubbed: str, signature_start: int) -> int | None:
    parentheses = 0
    brackets = 0
    angles = 0
    index = signature_start
    while index < len(scrubbed):
        character = scrubbed[index]
        if character == "(":
            parentheses += 1
        elif character == ")":
            parentheses = max(0, parentheses - 1)
        elif character == "[":
            brackets += 1
        elif character == "]":
            brackets = max(0, brackets - 1)
        elif character == "<" and parentheses == 0 and brackets == 0:
            angles += 1
        elif character == ">" and angles > 0 and not (
            index > 0 and scrubbed[index - 1] == "-"
        ):
            angles -= 1
        elif character == "{" and parentheses == 0 and brackets == 0 and angles == 0:
            return index
        elif character == ";" and parentheses == 0 and brackets == 0 and angles == 0:
            return None
        index += 1
    return None


def production_functions(source: str) -> list[tuple[str, int, int]]:
    scrubbed = scrub_rust(source)
    spans = test_spans(scrubbed)
    functions: list[tuple[str, int, int]] = []
    for match in FUNCTION.finditer(scrubbed):
        if in_spans(match.start(), spans) or has_test_attribute(scrubbed, match.start()):
            continue
        opening = function_body_start(scrubbed, match.end())
        if opening is None:
            continue
        closing = matching_brace(scrubbed, opening)
        if closing is None:
            functions.append((match.group(1), line_number(source, match.start()), sys.maxsize))
            continue
        start_line = line_number(source, match.start())
        end_line = line_number(source, closing)
        functions.append((match.group(1), start_line, end_line - start_line + 1))
    return functions


def parse_use_tree(tokens: list[str]) -> list[tuple[str, ...]]:
    position = 0

    def parse_group(prefix: tuple[str, ...]) -> list[tuple[str, ...]]:
        nonlocal position
        paths: list[tuple[str, ...]] = []
        if position < len(tokens) and tokens[position] == "{":
            position += 1
        while position < len(tokens) and tokens[position] != "}":
            paths.extend(parse_tree(prefix))
            if position < len(tokens) and tokens[position] == ",":
                position += 1
        if position < len(tokens) and tokens[position] == "}":
            position += 1
        return paths

    def parse_tree(prefix: tuple[str, ...]) -> list[tuple[str, ...]]:
        nonlocal position
        if position >= len(tokens):
            return []
        if tokens[position] == "{":
            return parse_group(prefix)
        segment = tokens[position]
        position += 1
        if segment == "*":
            return [prefix + ("*",)]
        path = prefix if segment == "self" else prefix + (segment,)
        if position < len(tokens) and tokens[position] == "as":
            position += 2
            return [path]
        if position < len(tokens) and tokens[position] == "::":
            position += 1
            return parse_tree(path)
        return [path]

    expanded: list[tuple[str, ...]] = []
    while position < len(tokens):
        if tokens[position] in {",", "}"}:
            position += 1
            continue
        expanded.extend(parse_tree(()))
    return expanded


def imports(scrubbed: str) -> list[tuple[int, tuple[str, ...]]]:
    result: list[tuple[int, tuple[str, ...]]] = []
    for statement in USE_STATEMENT.finditer(scrubbed):
        if has_test_attribute(scrubbed, statement.start()):
            continue
        tokens = USE_TOKEN.findall(statement.group("body"))
        for path in parse_use_tree(tokens):
            result.append((line_number(scrubbed, statement.start()), path))
    return result


def module_scope(path: str) -> str | None:
    if path == "src/public_upload_transport.rs" or path.startswith(
        "src/public_upload_transport/"
    ):
        return "shared_transport"
    if path == "src/api.rs" or path.startswith("src/api/"):
        return "api"
    if path == "src/db.rs" or path.startswith("src/db/"):
        return "db"
    if path == "src/secure_fs.rs" or path.startswith("src/secure_fs/"):
        return "secure_fs"
    if path.startswith("src/services/"):
        return "services"
    return None


def is_test_module(path: str) -> bool:
    relative = Path(path)
    return (
        "tests" in relative.parts
        or relative.name == "tests.rs"
        or relative.name == "test_support.rs"
        or relative.name.endswith("_tests.rs")
    )


def path_violations(path: str, source: str) -> list[Violation]:
    if is_test_module(path):
        return []
    scope = module_scope(path)
    scrubbed = scrub_rust(source)
    for start, end in reversed(test_spans(scrubbed)):
        scrubbed = scrubbed[:start] + "".join(
            "\n" if character == "\n" else " " for character in scrubbed[start:end]
        ) + scrubbed[end:]

    violations: set[Violation] = set()
    if path == "src/api.rs" or path.startswith("src/api/") or path == "src/web.rs" or path.startswith("src/web/"):
        for match in re.finditer(r"\bState\s*<\s*(?:crate\s*::\s*)?AppState\s*>", scrubbed):
            violations.add(
                Violation(
                    path,
                    line_number(scrubbed, match.start()),
                    "ARCH-STATE-EXTRACTOR",
                    "HTTP handlers must extract a narrow FromRef route state",
                )
            )
        if path not in STATE_BORROW_BOUNDARIES:
            for match in re.finditer(r"(?:\.\s*borrow\s*\(|\bBorrow\s*::\s*borrow\s*\()", scrubbed):
                violations.add(
                    Violation(
                        path,
                        line_number(scrubbed, match.start()),
                        "ARCH-STATE-ESCAPE",
                        "HTTP adapters may not escape a narrow route state through Borrow<AppState>",
                    )
                )
    if path == "src/state/routes.rs":
        for match in re.finditer(r"\bimpl\b[^{};]*\bDeref\b[^{};]*\bRouteState\b", scrubbed):
            violations.add(
                Violation(
                    path,
                    line_number(scrubbed, match.start()),
                    "ARCH-STATE-DEREF",
                    "narrow route states may not dereference to AppState",
                )
            )

    if scope is None:
        return sorted(violations)

    for line, imported in imports(scrubbed):
        segments = tuple(segment for segment in imported if segment not in {"self", "*"})
        crate_module = None
        if segments and segments[0] == "crate" and len(segments) > 1:
            crate_module = segments[1]
        elif segments and segments[0] in {"api", "web"}:
            crate_module = segments[0]
        elif segments and all(segment == "super" for segment in segments[:-1]):
            crate_module = segments[-1]

        service_http_auth_permit = (
            len(segments) == 3
            and segments[:2] == ("crate", "http_auth")
            and segments[2] in SERVICE_HTTP_AUTH_PERMITS
        )
        if scope == "services" and (
            crate_module in {"api", "web"}
            or (crate_module == "http_auth" and not service_http_auth_permit)
        ):
            violations.add(
                Violation(path, line, "ARCH-IMPORT-SERVICE", f"services may not import {crate_module}")
            )
        if scope == "api" and crate_module == "web":
            violations.add(Violation(path, line, "ARCH-IMPORT-API", "API may not import web"))
        if scope == "shared_transport" and crate_module in {"api", "web"}:
            violations.add(
                Violation(
                    path,
                    line,
                    "ARCH-IMPORT-TRANSPORT",
                    f"shared transport may not import adapter {crate_module}",
                )
            )
        if scope in {"db", "secure_fs"} and (
            crate_module in {"api", "web"} or (segments and segments[0] in TRANSPORT_CRATES)
        ):
            target = crate_module or segments[0]
            violations.add(
                Violation(
                    path,
                    line,
                    "ARCH-IMPORT-TRANSPORT",
                    f"{scope} may not import transport layer {target}",
                )
            )
        if scope == "services" and segments and segments[0] in {"askama", "axum"}:
            violations.add(
                Violation(
                    path,
                    line,
                    "ARCH-IMPORT-SERVICE",
                    f"services may not import transport crate {segments[0]}",
                )
            )

    direct_patterns: list[tuple[re.Pattern[str], str, set[str]]] = []
    if scope == "services":
        for match in re.finditer(
            r"\b(?:release_session_audited|release_session_audit_decision|"
            r"required_session_audit_result_job|run_required_session_audit|"
            r"into_legacy_inner|into_test_value)\b",
            scrubbed,
        ):
            violations.add(
                Violation(
                    path,
                    line_number(scrubbed, match.start()),
                    "ARCH-AUDIT-PROOF",
                    "services must preserve required-audit proofs for their adapters",
                )
            )
        for match in re.finditer(
            r"\b(?:crate|super(?:::\s*super)*)\s*::\s*http_auth\s*::\s*"
            r"([A-Za-z_][A-Za-z0-9_]*)",
            scrubbed,
        ):
            if match.group(1) not in SERVICE_HTTP_AUTH_PERMITS:
                violations.add(
                    Violation(
                        path,
                        line_number(scrubbed, match.start()),
                        "ARCH-IMPORT-SERVICE",
                        "services may not reference http_auth",
                    )
                )
        direct_patterns.append(
            (
                re.compile(r"\b(?:crate|super(?:::\s*super)*)\s*::\s*(api|web)\b"),
                "ARCH-IMPORT-SERVICE",
                {"api", "web"},
            )
        )
    if scope == "api":
        direct_patterns.append(
            (re.compile(r"\b(?:crate|super(?:::\s*super)*)\s*::\s*(web)\b"), "ARCH-IMPORT-API", {"web"})
        )
    if scope == "shared_transport":
        direct_patterns.append(
            (
                re.compile(r"\b(?:crate|super(?:::\s*super)*)\s*::\s*(api|web)\b"),
                "ARCH-IMPORT-TRANSPORT",
                {"api", "web"},
            )
        )
    if scope in {"db", "secure_fs"}:
        direct_patterns.extend(
            [
                (
                    re.compile(r"\b(?:crate|super(?:::\s*super)*)\s*::\s*(api|web)\b"),
                    "ARCH-IMPORT-TRANSPORT",
                    {"api", "web"},
                ),
                (
                    re.compile(
                        r"\b(askama|axum|http|http_body|http_body_util|hyper|tower)\s*::"
                    ),
                    "ARCH-IMPORT-TRANSPORT",
                    TRANSPORT_CRATES,
                ),
            ]
        )
    for pattern, code, _targets in direct_patterns:
        for match in pattern.finditer(scrubbed):
            target = match.group(1)
            violations.add(
                Violation(
                    path,
                    line_number(scrubbed, match.start()),
                    code,
                    f"{scope} may not reference {target}",
                )
            )
    return sorted(violations)


def load_allowlist(path: Path, root: Path) -> tuple[dict[str, DataFileAllowance], list[Violation]]:
    violations: list[Violation] = []
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=unique_object
        )
    except (OSError, json.JSONDecodeError, DuplicateKeyError) as error:
        return {}, [Violation(path.as_posix(), 1, "ARCH-ALLOWLIST", f"cannot read allowlist: {error}")]
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        return {}, [Violation(path.as_posix(), 1, "ARCH-ALLOWLIST", "schema_version must be 1")]
    if set(document) != {"schema_version", "data_files"}:
        violations.append(
            Violation(path.as_posix(), 1, "ARCH-ALLOWLIST", "unexpected top-level keys")
        )
    entries = document.get("data_files")
    if not isinstance(entries, list):
        return {}, violations + [
            Violation(path.as_posix(), 1, "ARCH-ALLOWLIST", "data_files must be an array")
        ]

    result: dict[str, DataFileAllowance] = {}
    for index, entry in enumerate(entries):
        label = f"data_files[{index}]"
        if not isinstance(entry, dict) or set(entry) != {"path", "max_lines", "reason"}:
            violations.append(
                Violation(path.as_posix(), 1, "ARCH-ALLOWLIST", f"{label} has invalid keys")
            )
            continue
        relative = entry.get("path")
        maximum = entry.get("max_lines")
        reason = entry.get("reason")
        valid_path = (
            isinstance(relative, str)
            and relative.startswith("src/")
            and relative.endswith(".rs")
            and ".." not in Path(relative).parts
        )
        if not valid_path:
            violations.append(
                Violation(path.as_posix(), 1, "ARCH-ALLOWLIST", f"{label} has an unsafe path")
            )
            continue
        if relative in result:
            violations.append(
                Violation(path.as_posix(), 1, "ARCH-ALLOWLIST", f"duplicate entry for {relative}")
            )
            continue
        if not isinstance(maximum, int) or isinstance(maximum, bool) or not (
            1 <= maximum <= ALLOWLIST_MAX_LINES
        ):
            violations.append(
                Violation(path.as_posix(), 1, "ARCH-ALLOWLIST", f"{label} has an invalid max_lines")
            )
            continue
        if not isinstance(reason, str) or len(reason.strip()) < 30:
            violations.append(
                Violation(path.as_posix(), 1, "ARCH-ALLOWLIST", f"{label} needs a specific reason")
            )
            continue
        target = root / relative
        if not target.is_file() or target.is_symlink():
            violations.append(
                Violation(path.as_posix(), 1, "ARCH-ALLOWLIST", f"{relative} is missing or unsafe")
            )
            continue
        result[relative] = DataFileAllowance(relative, maximum, reason.strip())
    return result, violations


def check(root: Path, allowlist_path: Path) -> list[Violation]:
    allowances, violations = load_allowlist(allowlist_path, root)
    seen_allowances: set[str] = set()
    source_root = root / "src"
    if not source_root.is_dir():
        return violations + [Violation("src", 1, "ARCH-READ", "source directory is missing")]

    for source_path in sorted(source_root.rglob("*.rs")):
        relative = source_path.relative_to(root).as_posix()
        if source_path.is_symlink() or not source_path.is_file():
            violations.append(Violation(relative, 1, "ARCH-READ", "source must be a regular file"))
            continue
        try:
            source = source_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            violations.append(Violation(relative, 1, "ARCH-READ", f"cannot read UTF-8 source: {error}"))
            continue
        physical_lines = len(source.splitlines())
        test_module = is_test_module(relative)
        ordinary_limit = TEST_MODULE_MAX_LINES if test_module else PRODUCTION_MODULE_MAX_LINES
        allowance = allowances.get(relative)
        effective_limit = ordinary_limit
        if allowance is not None:
            seen_allowances.add(relative)
            effective_limit = allowance.max_lines
            scrubbed = scrub_rust(source)
            if re.search(r"\b(?:fn|impl|macro_rules|mod|trait)\b", scrubbed):
                violations.append(
                    Violation(
                        relative,
                        1,
                        "ARCH-ALLOWLIST-CODE",
                        "data-file allowlist may not cover executable Rust items",
                    )
                )
        if physical_lines > effective_limit:
            kind = "test" if test_module else "production"
            violations.append(
                Violation(
                    relative,
                    1,
                    "ARCH-MODULE-LINES",
                    f"{kind} module has {physical_lines} physical lines; limit is {effective_limit}",
                )
            )
        if allowance is not None and physical_lines <= ordinary_limit:
            violations.append(
                Violation(relative, 1, "ARCH-ALLOWLIST-STALE", "data-file allowance is no longer needed")
            )

        if not test_module:
            for name, start_line, lines in production_functions(source):
                if lines > PRODUCTION_FUNCTION_MAX_LINES:
                    rendered = "an unterminated body" if lines == sys.maxsize else f"{lines} lines"
                    violations.append(
                        Violation(
                            relative,
                            start_line,
                            "ARCH-FUNCTION-LINES",
                            f"function {name} spans {rendered}; limit is {PRODUCTION_FUNCTION_MAX_LINES}",
                        )
                    )
        violations.extend(path_violations(relative, source))

    for unused in sorted(set(allowances) - seen_allowances):
        violations.append(
            Violation(unused, 1, "ARCH-ALLOWLIST-UNUSED", "allowlist entry was not evaluated")
        )
    return sorted(set(violations))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--allowlist", type=Path)
    parser.add_argument("--json", action="store_true", dest="json_output")
    arguments = parser.parse_args()

    root = arguments.root.resolve()
    allowlist = arguments.allowlist
    if allowlist is None:
        allowlist = root / "tools/architecture-allowlist.json"
    elif not allowlist.is_absolute():
        allowlist = root / allowlist
    violations = check(root, allowlist)

    if arguments.json_output:
        print(
            json.dumps(
                {
                    "ok": not violations,
                    "limits": {
                        "production_module_lines": PRODUCTION_MODULE_MAX_LINES,
                        "test_module_lines": TEST_MODULE_MAX_LINES,
                        "production_function_lines": PRODUCTION_FUNCTION_MAX_LINES,
                    },
                    "violations": [asdict(violation) for violation in violations],
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        for violation in violations:
            print(
                f"{violation.path}:{violation.line}: {violation.code}: {violation.message}",
                file=sys.stderr,
            )
        if violations:
            print(f"architecture policy: {len(violations)} violation(s)", file=sys.stderr)
        else:
            print("Architecture policy checks passed")
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
