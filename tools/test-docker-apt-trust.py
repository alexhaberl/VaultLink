#!/usr/bin/env python3
"""Offline APT authentication with an appended untrusted signing certificate."""
from datetime import datetime, timezone
from email.utils import format_datetime
import hashlib
import os
from pathlib import Path
import pwd
import re
import subprocess
import tempfile
import unittest


SCRIPT = Path(os.environ.get("TEST_ROOTLESS_SCRIPT",
                            Path(__file__).with_name("docker-rootless-smoke.sh")))
PIN = "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"


class AptTrustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="vaultlink-apt-trust-")
        cls.root = Path(cls.temporary.name)
        cls.home = cls.root / "gnupg"
        cls.home.mkdir(mode=0o700)
        cls.env = {**os.environ, "GNUPGHOME": str(cls.home)}
        cls.gpg("--quick-generate-key", "Fixture trusted", "ed25519", "cert,sign", "0")
        cls.gpg("--quick-generate-key", "Fixture unrelated", "ed25519", "sign", "0")
        keys = cls.gpg("--with-colons", "--list-keys").stdout.decode()
        cls.trusted, cls.unrelated = re.findall(r"^fpr:::::::::([A-F0-9]+):", keys, re.M)
        cls.gpg("--quick-add-key", cls.trusted, "ed25519", "sign", "0")
        keys = cls.gpg("--with-colons", "--list-keys", cls.trusted).stdout.decode()
        cls.subkey = re.findall(r"^fpr:::::::::([A-F0-9]+):", keys, re.M)[1]
        cls.keyring = cls.root / "combined.asc"
        # Keep the expected certificate first, exactly as in the reported bypass.
        cls.keyring.write_bytes(cls.gpg("--armor", "--export", cls.trusted).stdout
                                + cls.gpg("--armor", "--export", cls.unrelated).stdout)
        cls.arch = subprocess.check_output(["dpkg", "--print-architecture"], text=True).strip()
        cls.repository = cls.root / "repository"
        cls.dist = cls.repository / "dists/noble"
        packages = cls.dist / f"stable/binary-{cls.arch}/Packages"
        packages.parent.mkdir(parents=True)
        packages.write_bytes(b"")
        relative = packages.relative_to(cls.dist)
        cls.release = cls.dist / "Release"
        cls.release.write_text(
            "Origin: VaultLink offline fixture\nLabel: Fixture\nSuite: noble\nCodename: noble\n"
            f"Date: {format_datetime(datetime.now(timezone.utc), usegmt=True)}\n"
            f"Architectures: {cls.arch}\nComponents: stable\n"
            f"MD5Sum:\n {hashlib.md5(b'', usedforsecurity=False).hexdigest()} 0 {relative}\n"
            f"SHA256:\n {hashlib.sha256(b'').hexdigest()} 0 {relative}\n")

    @classmethod
    def gpg(cls, *args):
        return subprocess.run(["gpg", "--batch", "--yes", "--pinentry-mode", "loopback",
                               "--passphrase", "", *args],
                              env=cls.env, capture_output=True, check=True, timeout=20)

    @classmethod
    def tearDownClass(cls):
        subprocess.run(["gpgconf", "--kill", "all"], env=cls.env, check=True, timeout=5)
        cls.temporary.cleanup()

    def authenticate(self, signer, restrict=True):
        self.gpg("--armor", "--local-user", signer + "!", "--output",
                 str(self.dist / "InRelease"), "--clearsign", str(self.release))
        # Execute the actual deb822 printf from the bootstrap, replacing only
        # its fixture key identity, keyring location and outbound repository URL.
        source = SCRIPT.read_text()
        expression = re.search(r"^  (printf 'Types: deb.*?)(?=\s+\| sudo tee)",
                               source, re.M | re.S).group(1).rstrip().removesuffix("\\").rstrip()
        expression = expression.replace(PIN, self.trusted)
        expression = expression.replace("/etc/apt/keyrings/vaultlink-docker-ci.asc", str(self.keyring))
        expression = expression.replace("https://download.docker.com/linux/ubuntu",
                                        self.repository.as_uri())
        if not restrict:
            expression = expression.replace(" " + self.trusted, "")
        with tempfile.TemporaryDirectory(dir=self.root) as temporary:
            work = Path(temporary)
            sources = work / "fixture.sources"
            sources.write_text(subprocess.check_output(["bash", "-c", expression], text=True))
            lists = work / "lists"
            lists.mkdir()
            (lists / "partial").mkdir()
            result = subprocess.run([
                "apt-get", "-o", f"Dir::Etc::sourcelist={sources}",
                "-o", "Dir::Etc::sourceparts=-", "-o", "Dir::Etc::trustedparts=-",
                "-o", f"Dir::Etc::trusted={work / 'unused.gpg'}",
                "-o", f"Dir::State::lists={lists}", "-o", f"Dir::Cache={work}",
                "-o", f"APT::Sandbox::User={pwd.getpwuid(os.getuid()).pw_name}",
                "-o", "APT::Get::List-Cleanup=0", "update"],
                capture_output=True, text=True, timeout=15)
            return result

    def test_trusted_primary_key_authenticates(self):
        result = self.authenticate(self.trusted)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_trusted_signing_subkey_authenticates(self):
        result = self.authenticate(self.subkey)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_appended_key_is_rejected_but_old_path_trusts_it(self):
        self.assertEqual(self.authenticate(self.unrelated, restrict=False).returncode, 0)
        result = self.authenticate(self.unrelated)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
