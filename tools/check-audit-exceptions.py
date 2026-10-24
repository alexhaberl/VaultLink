#!/usr/bin/env python3
"""Keep reviewed timing advisories confined to WebAuthn public-key verification."""
import argparse
from pathlib import Path
import re
import shlex
import sys
import tomllib


ADVISORIES = ["RUSTSEC-2023-0071", "RUSTSEC-2026-0387"]
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
# Versions, published bytes, and every incoming edge reviewed on 2026-10-24.
# A new consumer or even a patched version needs an explicit reassessment.
REVIEWED = {
    "crypto-bigint": ("0.5.5", "0dc92fb57ca44df6db8059111ab3af99a63d5d0f8375d9972e319a379c6bab76", {"elliptic-curve"}),
    "elliptic-curve": ("0.13.8", "b5e6043086bf7973472e0c7dff2142ea0b680d30e18d9cc40f267efbf222bd47", {"ecdsa", "p256", "p384", "primeorder"}),
    "ecdsa": ("0.16.9", "ee27f32b5c5292967d2d4a9d7f1e0b0aed2c15daded5a60300e4abb9d8020bca", {"p256", "p384"}),
    "primeorder": ("0.13.6", "353e1ca18966c16d9deb1c69278edbc5f194139612772bd9537af60ac231e1e6", {"p256", "p384"}),
    "p256": ("0.13.2", "c9863ad85fa8f4460f9c48cb909d38a0d689dba1f6f6988a5e3e0d31071bcd4b", {"webauthn_rp"}),
    "p384": ("0.13.1", "fe42f1670a52a47d448f14b6a5c61dd78fce51856e68edaa38f7ae3a46b8d6b6", {"webauthn_rp"}),
    "rsa": ("0.9.10", "b8573f03f5883dcaebdfcf4725caa1ecb9c15b2ef50c43a07b816e06799bb12d", {"webauthn_rp"}),
    "webauthn_rp": ("0.3.0", "a3a3b672b5e6ffc799106fb40c86d5787e331d5491452ffc3eb616b418e04e85", {"vaultlink"}),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check(root):
    config = tomllib.loads((root / ".cargo/audit.toml").read_text(encoding="utf-8"))
    require(config == {"advisories": {"ignore": ADVISORIES}},
            "audit config must contain exactly the two reviewed WebAuthn timing exceptions")

    expected_command = ["cargo", "audit", "--deny", "warnings"]
    for advisory in ADVISORIES:
        expected_command += ["--ignore", advisory]
    commands = []
    for path in [*sorted((root / ".github/workflows").glob("*.y*ml")),
                 root / "tools/audit-release-candidate.sh"]:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.lstrip().startswith("#"):
                continue
            match = re.match(r"^\s*(?:run:\s*)?(cargo\s+audit(?:\s|$).*)", line)
            if match:
                command = shlex.split(match.group(1).rstrip().removesuffix("\\"))
                require(command == expected_command,
                        f"{path.name}: audit must deny warnings and use exactly the reviewed exceptions")
                commands.append(path.relative_to(root).as_posix())
    require(sorted(commands) == [".github/workflows/ci.yml", "tools/audit-release-candidate.sh"],
            "native CI and the frozen-candidate audit must both enforce the reviewed exceptions")


    check_dependencies(root)


def check_dependencies(root):
    packages = tomllib.loads((root / "Cargo.lock").read_text(encoding="utf-8"))["package"]
    for name, (version, checksum, expected_parents) in REVIEWED.items():
        matches = [package for package in packages if package["name"] == name]
        require(len(matches) == 1, f"{name}: exactly one reviewed version is required")
        package = matches[0]
        require(package["version"] == version and package.get("source") == REGISTRY
                and package.get("checksum") == checksum,
                f"{name}: version or published source changed; reassess the timing exception")
        parents = [parent for parent in packages
                   if any(dep.split(" ", 1)[0] == name for dep in parent.get("dependencies", []))]
        require(len(parents) == len(expected_parents)
                and {parent["name"] for parent in parents} == expected_parents,
                f"{name}: dependency path changed; exception covers only WebAuthn public-key verification")

    manifest = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    require(manifest["dependencies"]["webauthn_rp"] == {
        "version": "=0.3.0", "default-features": False, "features": ["bin", "serde_relaxed"],
    }, "webauthn_rp features changed; review the verification-only exception")

    # Cargo.lock does not record features. Alternate/aliased declarations in
    # dev, build, workspace, or target tables can otherwise enable new ones
    # without adding an incoming lockfile edge.
    protected = {name.replace("_", "-") for name in REVIEWED}
    contexts = [("root", manifest), ("workspace", manifest.get("workspace", {}))]
    contexts += [(f"target {target}", tables)
                 for target, tables in manifest.get("target", {}).items()]
    for context, tables in contexts:
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            for alias, spec in tables.get(section, {}).items():
                package = spec.get("package", alias) if isinstance(spec, dict) else alias
                if package.replace("_", "-") in protected:
                    require((context, section, alias) == ("root", "dependencies", "webauthn_rp"),
                            "alternate crypto dependency declaration changed; reassess features and secret use")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--dependencies-only", action="store_true",
                        help="check frozen candidate metadata without trusting its audit settings")
    args = parser.parse_args()
    try:
        checker = check_dependencies if args.dependencies_only else check
        checker(args.root.resolve())
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"audit exception policy: {error}", file=sys.stderr)
        return 1
    print("audit exception policy: reviewed WebAuthn-only paths and exceptions OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
