#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Fail-closed tripwire for one reviewed public-verification-only advisory scope.

RUSTSEC-2023-0071 is NOT patched. The pinned SEV cert_nossl verifier uses
RsaPublicKey -> PSS/SHA-384 VerifyingKey -> verify_digest -> rsa_encrypt(e, n).
The exact hashed collateral module uses that same public-only path for ARK CRLs;
neither path performs RSA private-key operations. The separately hashed guest
module only opens the fixed device and calls get_report: at the same SEV pin,
src/firmware/guest/mod.rs open/get_report and linux/guest/{types,ioctl}.rs use
SNP_GET_REPORT with a fixed report buffer, not RSA or certificate operations.
Changes require source review, not a broader exception. This is a source/graph
guard, not a general Rust call analyzer.
"""
import copy
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
ADVISORY = "RUSTSEC-2023-0071"
REVISION = "a966d06d9bf0e68afe2733e7bfbf278fd7fd65b5"
GIT = "https://github.com/virtee/sev"
SOURCE = f"git+{GIT}?rev={REVISION}#{REVISION}"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
RSA_CHECKSUM = "b8573f03f5883dcaebdfcf4725caa1ecb9c15b2ef50c43a07b816e06799bb12d"
SNP = Path("crates/volparossa-content/src/provider/compute/attestation/snp.rs")
SNP_CHECKSUM = "fa9d0aa97897c4bce02f8b7e4afd06901b5bc04880d5b51b0542c753fb79981c"
COLLATERAL = SNP.with_name("collateral.rs")
COLLATERAL_CHECKSUM = "c718d3fb5f1d58795ede17ad3e7e34871d3cb95331e39994e1744fc924b78b24"
GUEST = SNP.parent.parent / "guest.rs"
GUEST_CHECKSUM = "c5f7c8e378c697f6c9b109cb41380eeee72f409651f5bd4d01b183233efe97cb"
CONTENT = Path("crates/volparossa-content/Cargo.toml")
MARKER = "  # Root-only public RSA exception: scripts/check-public-rsa-scope.py must pass."
SEV_MANIFEST = dict(version="=8.0.0", git=GIT, rev=REVISION, **{"default-features": False},
    features=["snp", "crypto_nossl"])
RSA_MANIFEST = dict(version="=0.9.10", **{"default-features": False}, features=["std"])
CRYPTO = {"p384": "0.13.1", "rsa": "0.9.10", "sha2": "0.10.9", "x509-cert": "0.2.5"}


def require(condition):
    if not condition:
        raise ValueError("PUBLIC_RSA_SCOPE_CHANGED")


def read_toml(path):
    return tomllib.loads(path.read_text())


def one(packages, name):
    matches = [p for p in packages if p["name"] == name]
    require(len(matches) == 1)
    return matches[0]


def verify_repository(root):
    require(hashlib.sha256((root / SNP).read_bytes()).hexdigest() == SNP_CHECKSUM)
    require(hashlib.sha256((root / COLLATERAL).read_bytes()).hexdigest() == COLLATERAL_CHECKSUM)
    # Only this exact reviewed firmware wrapper, never its directory or future APIs.
    require(hashlib.sha256((root / GUEST).read_bytes()).hexdigest() == GUEST_CHECKSUM)
    # This sole existing fixture import is test-only, not another production user.
    parent = root / SNP.parent.with_suffix(".rs")
    require(re.search(r"#\[cfg\(test\)\]\s*mod tests;", parent.read_text()) is not None)
    fixture = SNP.parent / "tests.rs"
    for path in (root / "crates").rglob("*.rs"):
        if path.relative_to(root) not in (SNP, COLLATERAL, GUEST, fixture):
            require(re.search(r"\b(?:sev|rsa)\b", path.read_text()) is None)

    def dependencies(value, location):
        for key, item in value.items():
            if key in ("dependencies", "dev-dependencies", "build-dependencies"):
                for name, declaration in item.items():
                    package = declaration.get("package", name) if isinstance(declaration, dict) else name
                    if name in ("sev", "rsa") or package in ("sev", "rsa"):
                        yield location + (key, name), declaration
            elif isinstance(item, dict):
                yield from dependencies(item, location + (key,))

    observed = []
    manifests = [root / "Cargo.toml", root / "fuzz/Cargo.toml", *(root / "crates").rglob("Cargo.toml")]
    for manifest in manifests:
        observed.extend((manifest.relative_to(root).as_posix(), loc, declaration)
            for loc, declaration in dependencies(read_toml(manifest), ()))
    require(observed == [("Cargo.toml", ("workspace", "dependencies", "rsa"), RSA_MANIFEST),
        ("Cargo.toml", ("workspace", "dependencies", "sev"), SEV_MANIFEST),
        (CONTENT.as_posix(), ("dependencies", "rsa"), {"workspace": True}),
        (CONTENT.as_posix(), ("dependencies", "sev"), {"workspace": True})])
    lock = read_toml(root / "Cargo.lock")["package"]
    rsa, sev = one(lock, "rsa"), one(lock, "sev")
    require((rsa["version"], rsa["source"], rsa["checksum"]) == ("0.9.10", REGISTRY, RSA_CHECKSUM))
    require((sev["version"], sev["source"]) == ("8.0.0", SOURCE))
    for child, parent_names in (("rsa", ["sev", "volparossa-content"]), ("sev", ["volparossa-content"])):
        parents = [p["name"] for p in lock if any(d.split()[0] == child for d in p.get("dependencies", []))]
        require(parents == parent_names)
    require(not any(p["name"] in ("rsa", "sev") for p in read_toml(root / "fuzz/Cargo.lock")["package"]))


def verify_metadata(root, metadata, fuzz):
    require(metadata["workspace_root"] == str(root) and fuzz["workspace_root"] == str(root / "fuzz"))
    require(not any(p["name"] in ("rsa", "sev") for p in fuzz["packages"]))
    packages = metadata["packages"]
    ids = {p["id"]: p for p in packages}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    require(len(ids) == len(packages) and len(nodes) == len(metadata["resolve"]["nodes"]))
    rsa, sev, content = (one(packages, name) for name in ("rsa", "sev", "volparossa-content"))
    require((rsa["version"], rsa["source"]) == ("0.9.10", REGISTRY))
    require((sev["version"], sev["source"]) == ("8.0.0", SOURCE))
    require(content["version"] == "0.1.0" and content["source"] is None
        and content["manifest_path"] == str(root / CONTENT) and content["id"] in metadata["workspace_members"])
    require(sorted(nodes[sev["id"]]["features"]) == ["crypto_nossl", "snp"])
    require(sev["features"]["crypto_nossl"] == ["dep:p384", "dep:rsa", "dep:sha2", "dep:x509-cert"]
        and sev["features"]["snp"] == [])
    for node in nodes.values():
        require(node["id"] in ids and all(d["pkg"] in ids for d in node["deps"]))
        require(len(node["dependencies"]) == len(set(node["dependencies"]))
            and set(node["dependencies"]) == {d["pkg"] for d in node["deps"]})
    lock = read_toml(root / "Cargo.lock")["package"]
    for name, version in CRYPTO.items():
        matches = [d for d in nodes[sev["id"]]["deps"] if d["name"] == name.replace("-", "_")]
        require(len(matches) == 1)
        dep = matches[0]
        package = ids[dep["pkg"]]
        require(package["name"] == name and package["version"] == version and package["source"] == REGISTRY
            and dep["dep_kinds"] == [dict(kind=None, target=None)] and dep["pkg"] in nodes
            and any(p["name"] == name and p["version"] == version and p.get("source") == REGISTRY for p in lock))
    for child, parents in ((rsa, [sev, content]), (sev, [content])):
        incoming = [(n["id"], d) for n in nodes.values() for d in n["deps"] if d["pkg"] == child["id"]]
        require(sorted(incoming, key=lambda value: value[0]) == sorted(
            [(parent["id"], dict(name=child["name"], pkg=child["id"],
                dep_kinds=[dict(kind=None, target=None)])) for parent in parents], key=lambda value: value[0]))
        require(child["id"] in nodes)


def root_deny_config(text):
    before = tomllib.loads(text)
    require(text.count(MARKER) == 1 and ADVISORY not in before["advisories"]["ignore"])
    result = text.replace(MARKER, f'{MARKER}\n  "{ADVISORY}",')
    expected = copy.deepcopy(before)
    expected["advisories"]["ignore"].insert(0, ADVISORY)
    require(tomllib.loads(result) == expected)
    return result


def main(arguments):
    require(len(arguments) == 3)
    verify_repository(ROOT)
    values = []
    for name in arguments[:2]:
        with Path(name).open("rb") as stream:
            raw = stream.read(8 * 1024 * 1024 + 1)
        require(len(raw) <= 8 * 1024 * 1024)
        values.append(json.loads(raw))
    verify_metadata(ROOT, *values)
    config = root_deny_config((ROOT / "deny.toml").read_text())
    # Created only in the caller's private audit directory, never overwrite policy.
    with Path(arguments[2]).open("x") as output:
        output.write(config)
    print("PASS  RUSTSEC-2023-0071 is non-applicable only to the pinned public RSA verifier; NOT patched; fuzz exception absent")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError, RecursionError):
        print("FAIL  public RSA scope changed; no advisory exception authorized", file=sys.stderr)
        sys.exit(1)
