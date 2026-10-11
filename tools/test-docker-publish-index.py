#!/usr/bin/env python3
"""Exercise the real index-assembly workflow with a local registry stand-in."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest


WORKFLOW = Path(os.environ.get("TEST_DOCKER_PUBLISH_WORKFLOW",
                              Path(__file__).resolve().parents[1] / ".github/workflows/docker-publish.yml"))


class PublishIndexTests(unittest.TestCase):
    def exercise(self, existing=True, changed=None, duplicate=False, unavailable=False):
        source = WORKFLOW.read_text()
        step = source.split("- name: Assemble and verify versioned multiarch image", 1)[1]
        script = textwrap.dedent(step.split("run: |\n", 1)[1].split("      - uses:", 1)[0])
        values = {"tag": "v0.7.2", "commit": "a" * 40, "amd64_hash": "b" * 64,
                  "arm64_hash": "c" * 64, "qualification_run": "123", "qualification_attempt": "2",
                  "amd64_artifact_sha": "d" * 64, "arm64_artifact_sha": "e" * 64}
        script = re.sub(r"\$\{\{ needs.prepare.outputs.(\w+) \}\}",
                        lambda match: values[match[1]], script)
        children = {"amd64": "sha256:" + "1" * 64, "arm64": "sha256:" + "2" * 64}
        builds = {"amd64": "sha256:" + "3" * 64, "arm64": "sha256:" + "4" * 64}
        index_digest = "sha256:" + "5" * 64
        manifests = [{"platform": {"os": "linux", "architecture": arch}, "digest": digest}
                     for arch, digest in children.items()]
        published = json.loads(json.dumps(manifests))
        if changed:
            published[0 if changed == "amd64" else 1]["digest"] = "sha256:" + "6" * 64
        if duplicate:
            published.append(published[0])
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            (work / "digests").mkdir()
            for arch in children:
                (work / "digests" / f"digest-{arch}").write_text(builds[arch])
                (work / "digests" / f"binary-{arch}.sha256").write_text(values[f"{arch}_hash"])
                (work / f"{arch}.json").write_text(json.dumps({"manifests": [
                    next(m for m in manifests if m["platform"]["architecture"] == arch),
                    {"platform": {"os": "unknown", "architecture": "unknown"},
                     "digest": "sha256:" + "7" * 64}]}))
            (work / "published.json").write_text(json.dumps({"manifests": published}))
            docker = work / "docker"
            docker.write_text("#!/usr/bin/env python3\n" + textwrap.dedent('''
                import os, pathlib, sys
                args = sys.argv[1:]
                if args[0] == 'login':
                    sys.stdin.read()
                    sys.exit(0)
                if args[:3] == ['buildx', 'imagetools', 'create']:
                    pathlib.Path('created').touch()
                    sys.exit(0)
                ref = args[3]
                for arch in ('amd64', 'arm64'):
                    if ref.endswith('@' + os.environ[arch.upper() + '_BUILD']):
                        print(pathlib.Path(arch + '.json').read_text())
                        sys.exit(0)
                if '--raw' in args:
                    pathlib.Path('raw-reference').write_text(ref)
                    print(pathlib.Path('published.json').read_text())
                    sys.exit(0)
                if os.environ['UNAVAILABLE'] == '1':
                    print('unauthorized', file=sys.stderr)
                    sys.exit(1)
                if os.environ['EXISTING'] == '0' and not pathlib.Path('created').exists():
                    print('manifest unknown', file=sys.stderr)
                    sys.exit(1)
                print('Digest: ' + os.environ['INDEX_DIGEST'])
                '''))
            docker.chmod(0o755)
            result = subprocess.run(["bash", "-c", script], cwd=work,
                env={**os.environ, "PATH": str(work) + os.pathsep + os.environ["PATH"],
                     "IMAGE": "ghcr.io/alexhaberl/vaultlink", "GH_TOKEN": "fixture",
                     "GITHUB_ACTOR": "fixture", "GITHUB_OUTPUT": str(work / "outputs"),
                     "AMD64_BUILD": builds["amd64"], "ARM64_BUILD": builds["arm64"],
                     "INDEX_DIGEST": index_digest, "EXISTING": str(int(existing)),
                     "UNAVAILABLE": str(int(unavailable))},
                capture_output=True, text=True, timeout=10)
            if changed or duplicate or unavailable:
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((work / "image-reference.txt").exists())
            else:
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((work / "created").exists(), not existing)
                self.assertEqual((work / "raw-reference").read_text(),
                                 "ghcr.io/alexhaberl/vaultlink@" + index_digest)
                evidence = (work / "image-reference.txt").read_text()
                for arch, digest in children.items():
                    self.assertIn(f"{arch}={digest}\n", evidence)
                    self.assertIn(f"{arch}_child_digest={digest}\n", (work / "outputs").read_text())

    def test_new_tag(self):
        self.exercise(existing=False)

    def test_existing_identical_tag(self):
        self.exercise()

    def test_existing_substituted_children(self):
        for architecture in ("amd64", "arm64"):
            with self.subTest(architecture=architecture):
                self.exercise(changed=architecture)

    def test_duplicate_native_manifest(self):
        self.exercise(duplicate=True)

    def test_registry_error_does_not_mean_absent(self):
        self.exercise(existing=False, unavailable=True)


if __name__ == "__main__":
    unittest.main()
