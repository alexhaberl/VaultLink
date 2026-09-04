#!/usr/bin/env python3
"""Focused parser and fail-closed policy tests for check-architecture.py."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


CHECKER_PATH = Path(__file__).with_name("check-architecture.py")
SPEC = importlib.util.spec_from_file_location("vaultlink_architecture_policy", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
POLICY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = POLICY
SPEC.loader.exec_module(POLICY)


class ArchitecturePolicyTests(unittest.TestCase):
    def test_scrubber_retains_offsets_and_ignores_nested_non_code_braces(self) -> None:
        source = '''fn sample() {
    let raw = r###"not code } /*"###;
    /* outer { /* nested } */ still comment */
    let character = '}';
}
'''
        scrubbed = POLICY.scrub_rust(source)
        self.assertEqual(len(scrubbed), len(source))
        self.assertEqual(scrubbed.count("\n"), source.count("\n"))
        self.assertEqual(POLICY.production_functions(source), [("sample", 1, 5)])

    def test_function_parser_ignores_test_items_but_measures_production(self) -> None:
        self.assertTrue(POLICY.is_test_module("src/example/test_support.rs"))
        production_lines = ["fn production() {"] + ["    work();"] * 151 + ["}"]
        source = "\n".join(
            production_lines
            + [
                "#[cfg(test)]",
                "mod tests {",
                "    fn very_long_test() {",
                *(["        work();"] * 200),
                "    }",
                "}",
                "#[test]",
                "fn standalone_test() {}",
            ]
        )
        functions = POLICY.production_functions(source)
        self.assertEqual(functions, [("production", 1, 153)])

    def test_nested_use_tree_is_expanded(self) -> None:
        tokens = POLICY.USE_TOKEN.findall(
            "crate::{db::Database, web::{self, files::Entry}, services as domain}"
        )
        self.assertEqual(
            POLICY.parse_use_tree(tokens),
            [
                ("crate", "db", "Database"),
                ("crate", "web"),
                ("crate", "web", "files", "Entry"),
                ("crate", "services"),
            ],
        )

    def test_layer_rules_cover_nested_imports_and_direct_paths(self) -> None:
        services = "use crate::{db::Database, web::{files::Entry}};\n"
        api = "fn response() { crate::web::render(); }\n"
        database = "use axum::{body::Body};\n"
        shared_transport = "use crate::web::public_upload::execute;\n"
        self.assertEqual(
            {item.code for item in POLICY.path_violations("src/services/share/mod.rs", services)},
            {"ARCH-IMPORT-SERVICE"},
        )
        permitted_admission = "use crate::http_auth::ShareActivityPermit;\n"
        self.assertEqual(
            POLICY.path_violations("src/services/transfer.rs", permitted_admission), []
        )
        http_auth_import = "use crate::http_auth::Result;\n"
        self.assertEqual(
            {
                item.code
                for item in POLICY.path_violations(
                    "src/services/share/mod.rs", http_auth_import
                )
            },
            {"ARCH-IMPORT-SERVICE"},
        )
        http_auth_runner = "async fn run() { crate::http_auth::database().await; }\n"
        self.assertEqual(
            {
                item.code
                for item in POLICY.path_violations(
                    "src/services/share/mod.rs", http_auth_runner
                )
            },
            {"ARCH-IMPORT-SERVICE"},
        )
        self.assertEqual(
            {item.code for item in POLICY.path_violations("src/api/files.rs", api)},
            {"ARCH-IMPORT-API"},
        )
        self.assertEqual(
            {item.code for item in POLICY.path_violations("src/db/audit.rs", database)},
            {"ARCH-IMPORT-TRANSPORT"},
        )
        self.assertEqual(
            {
                item.code
                for item in POLICY.path_violations(
                    "src/public_upload_transport/mod.rs", shared_transport
                )
            },
            {"ARCH-IMPORT-TRANSPORT"},
        )
        test_only_transport = """#[cfg(test)]
use axum::body::Body;
#[cfg(test)]
impl Fixture {
    fn response() { crate::web::render(); }
}
"""
        self.assertEqual(
            POLICY.path_violations("src/db/audit.rs", test_only_transport), []
        )
        production_only_transport = test_only_transport.replace("cfg(test)", "cfg(not(test))")
        self.assertIn(
            "ARCH-IMPORT-TRANSPORT",
            {
                item.code
                for item in POLICY.path_violations(
                    "src/db/audit.rs", production_only_transport
                )
            },
        )

    def test_route_state_policy_rejects_full_state_and_capability_escape(self) -> None:
        full_state = "async fn handler(State(state): State<AppState>) {}\n"
        self.assertEqual(
            {
                item.code
                for item in POLICY.path_violations("src/api/files.rs", full_state)
            },
            {"ARCH-STATE-EXTRACTOR"},
        )

        escaped = "fn handler(state: FileRouteState) { let _ = state.borrow(); }\n"
        self.assertEqual(
            {
                item.code
                for item in POLICY.path_violations("src/web/files.rs", escaped)
            },
            {"ARCH-STATE-ESCAPE"},
        )
        self.assertEqual(
            POLICY.path_violations("src/api/common.rs", escaped),
            [],
        )

        deref = "impl std::ops::Deref for RouteState<Files> { type Target = AppState; }\n"
        self.assertEqual(
            {
                item.code
                for item in POLICY.path_violations("src/state/routes.rs", deref)
            },
            {"ARCH-STATE-DEREF"},
        )

    def test_services_cannot_release_required_audit_proofs(self) -> None:
        for source in (
            "fn commit(value: Proof) { crate::db::release_session_audited(value); }\n",
            "fn commit(db: &Database) { db.run_required_session_audit(operation); }\n",
            "fn commit() { required_session_audit_result_job(operation); }\n",
        ):
            self.assertIn(
                "ARCH-AUDIT-PROOF",
                {
                    item.code
                    for item in POLICY.path_violations("src/services/share/mod.rs", source)
                },
            )

        adapter = "fn respond(value: Proof) { crate::db::release_session_audited(value); }\n"
        self.assertNotIn(
            "ARCH-AUDIT-PROOF",
            {
                item.code
                for item in POLICY.path_violations("src/api/shares.rs", adapter)
            },
        )

    def test_repository_check_enforces_module_and_function_limits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src/api/tests").mkdir(parents=True)
            (root / "src").mkdir(exist_ok=True)
            (root / "tools").mkdir()
            long_function = "\n".join(
                ["fn too_long() {"] + ["    call();"] * 150 + ["}"]
            )
            (root / "src/lib.rs").write_text(long_function, encoding="utf-8")
            (root / "src/api/tests/large.rs").write_text(
                "\n".join(["// test"] * 1_201), encoding="utf-8"
            )
            allowlist = root / "tools/architecture-allowlist.json"
            allowlist.write_text(
                json.dumps({"schema_version": 1, "data_files": []}), encoding="utf-8"
            )
            violations = POLICY.check(root, allowlist)
            self.assertIn("ARCH-FUNCTION-LINES", {item.code for item in violations})
            self.assertIn("ARCH-MODULE-LINES", {item.code for item in violations})

    def test_allowlist_only_accepts_necessary_pure_data_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "tools").mkdir()
            data_path = root / "src/generated_data.rs"
            data_path.write_text(
                "pub static VALUES: &[u8] = &[\n"
                + "    0,\n" * 1_000
                + "];\n",
                encoding="utf-8",
            )
            allowlist = root / "tools/architecture-allowlist.json"
            allowlist.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "data_files": [
                            {
                                "path": "src/generated_data.rs",
                                "max_lines": 1_100,
                                "reason": "Generated immutable byte table with no executable Rust items.",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(POLICY.check(root, allowlist), [])

            data_path.write_text(
                data_path.read_text(encoding="utf-8") + "fn executable() {}\n",
                encoding="utf-8",
            )
            self.assertIn(
                "ARCH-ALLOWLIST-CODE",
                {item.code for item in POLICY.check(root, allowlist)},
            )


if __name__ == "__main__":
    unittest.main()
