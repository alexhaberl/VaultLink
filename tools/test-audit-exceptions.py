#!/usr/bin/env python3
"""Regression tests for the scope of the reviewed WebAuthn timing exceptions."""
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("audit_exceptions", ROOT / "tools/check-audit-exceptions.py")
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


class ExceptionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for name in [".cargo/audit.toml", ".github/workflows/ci.yml", "Cargo.lock", "Cargo.toml",
                     "tools/audit-release-candidate.sh"]:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        self.lock = (self.root / "Cargo.lock").read_text(encoding="utf-8")

    def replace(self, name, before, after):
        path = self.root / name
        text = path.read_text(encoding="utf-8")
        self.assertIn(before, text)
        path.write_text(text.replace(before, after), encoding="utf-8")

    def mutate_package(self, name, mutation):
        blocks = self.lock.split("[[package]]")
        matches = [i for i, block in enumerate(blocks) if block.startswith(f'\nname = "{name}"\n')]
        self.assertEqual(len(matches), 1)
        index = matches[0]
        blocks[index] = mutation(blocks[index])
        (self.root / "Cargo.lock").write_text("[[package]]".join(blocks), encoding="utf-8")

    def test_reviewed_graph_and_audit_commands_pass(self):
        POLICY.check(self.root)

    def test_frozen_metadata_does_not_need_or_trust_candidate_policy_files(self):
        (self.root / ".cargo/audit.toml").write_text('invalid candidate config', encoding="utf-8")
        (self.root / "tools/audit-release-candidate.sh").write_text('exit 0', encoding="utf-8")
        POLICY.check_dependencies(self.root)

    def test_no_other_exception_or_suppression_is_allowed(self):
        path = self.root / ".cargo/audit.toml"
        original = path.read_text(encoding="utf-8")
        for addition in ['"RUSTSEC-2099-0001"', '"RUSTSEC-2026-0387"']:
            with self.subTest(addition=addition):
                path.write_text(original.replace('ignore = [', f'ignore = [{addition}, '), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, 'exactly the two reviewed'):
                    POLICY.check(self.root)
        path.write_text(original + '\n[output]\nquiet = true\n', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, 'exactly the two reviewed'):
            POLICY.check(self.root)

    def test_missing_reviewed_exception_is_rejected(self):
        self.replace('.cargo/audit.toml', ', "RUSTSEC-2026-0387"', '')
        with self.assertRaisesRegex(ValueError, 'exactly the two reviewed'):
            POLICY.check(self.root)

    def test_both_audit_entry_points_keep_exact_reviewed_flags(self):
        for name in ['.github/workflows/ci.yml', 'tools/audit-release-candidate.sh']:
            path = self.root / name
            original = path.read_text(encoding="utf-8")
            for before, after in [('--ignore RUSTSEC-2026-0387', ''),
                                  ('--deny warnings', ''),
                                  ('--deny warnings', '--deny warnings --ignore RUSTSEC-2099-0001')]:
                with self.subTest(name=name, before=before, after=after):
                    path.write_text(original.replace(before, after), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        POLICY.check(self.root)
            path.write_text(original, encoding="utf-8")

    def test_additional_audit_command_is_rejected(self):
        command = 'cargo audit --deny warnings --ignore RUSTSEC-2023-0071 --ignore RUSTSEC-2026-0387'
        (self.root / '.github/workflows/extra.yaml').write_text(command, encoding="utf-8")
        with self.assertRaisesRegex(ValueError, 'must both enforce'):
            POLICY.check(self.root)

    def test_every_crypto_package_rejects_another_consumer(self):
        for name in POLICY.REVIEWED:
            with self.subTest(name=name):
                (self.root / "Cargo.lock").write_text(self.lock +
                    f'\n[[package]]\nname = "other-consumer"\nversion = "1.0.0"\ndependencies = ["{name}"]\n',
                    encoding="utf-8")
                with self.assertRaisesRegex(ValueError, 'dependency path changed'):
                    POLICY.check_dependencies(self.root)

    def test_direct_application_curve_use_requires_reassessment(self):
        self.mutate_package('vaultlink', lambda block: block.replace('dependencies = [',
                                                                    'dependencies = [\n "p256",'))
        with self.assertRaisesRegex(ValueError, 'dependency path changed'):
            POLICY.check_dependencies(self.root)

    def test_versions_sources_and_published_bytes_are_pinned(self):
        for name, (version, checksum, _) in POLICY.REVIEWED.items():
            for before, after in [(f'version = "{version}"', 'version = "0.99.0"'),
                                  (checksum, '0' * 64),
                                  (POLICY.REGISTRY, 'git+https://example.invalid/crypto')]:
                with self.subTest(name=name, before=before):
                    self.mutate_package(name, lambda block: block.replace(before, after))
                    with self.assertRaisesRegex(ValueError, 'version or published source changed'):
                        POLICY.check_dependencies(self.root)

    def test_duplicate_crypto_version_is_rejected(self):
        with (self.root / 'Cargo.lock').open('a', encoding="utf-8") as lock:
            lock.write('\n[[package]]\nname = "crypto-bigint"\nversion = "0.7.6"\n')
        with self.assertRaisesRegex(ValueError, 'exactly one reviewed version'):
            POLICY.check_dependencies(self.root)

    def test_missing_crypto_package_requires_removing_or_reassessing_exception(self):
        blocks = self.lock.split('[[package]]')
        (self.root / 'Cargo.lock').write_text('[[package]]'.join(
            block for block in blocks if not block.startswith('\nname = "crypto-bigint"\n')),
            encoding="utf-8")
        with self.assertRaisesRegex(ValueError, 'exactly one reviewed version'):
            POLICY.check_dependencies(self.root)

    def test_webauthn_feature_changes_require_review(self):
        self.replace('Cargo.toml', 'features = ["bin", "serde_relaxed"]',
                     'features = ["bin", "serde_relaxed", "custom"]')
        with self.assertRaisesRegex(ValueError, 'features changed'):
            POLICY.check_dependencies(self.root)


if __name__ == '__main__':
    unittest.main()
