#!/usr/bin/env python3
"""Parallax Aegis - signed self-integrity and quarantine enforcement.

Aegis is the trust anchor around the Parallax Ultra frontend. It does not try
to make source code unmodifiable; instead it makes modification *useless*:

* a signed policy pins SHA-256 anchors for every security-critical file;
* the Ed25519 public key is embedded in this module AND stored on disk, so
  replacing either one breaks the anchor for this module or the policy check;
* when an anchor fails, the frontend still runs but stamps the generated
  manifest with ``verdict: quarantine``. The artifact looks normal to whoever
  patched the tool, but ``verify`` refuses it, so it can never be shipped;
* the server-side endpoint applies the same idea with replay protection,
  session/device binding and signed canary envelopes.

The policy private key is deliberately NOT stored in this repository. Rotate
it by generating a new keypair and re-signing a new policy file.

Commands:
    python3 scripts/parallax_aegis.py status    # JSON verdict for diagnostics
    python3 scripts/parallax_aegis.py enforce   # exit 0 trusted, 3 tampered
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

POLICY_SCHEMA = "parallax-aegis-policy-v1"
BLOCK_SCHEMA = "parallax-aegis-block-v1"
MAX_POLICY_BYTES = 256 * 1024

# Ed25519 public key (32 raw bytes, lowercase hex). The matching private key
# lives outside this repository and is used only to sign security/aegis-policy.json.
ROOT_PUBLIC_KEY_HEX = "4eef0ca92b061da11f7abf5348bd818fd576e327d4c853cda2b244578e63dbf5"


class AegisError(RuntimeError):
    pass


def _root_public_key() -> bytes:
    if not re.fullmatch(r"[0-9a-fA-F]{64}", ROOT_PUBLIC_KEY_HEX):
        raise AegisError("aegis root key is not configured")
    return bytes.fromhex(ROOT_PUBLIC_KEY_HEX)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def policy_paths(root: Path | None = None) -> tuple[Path, Path, Path]:
    base = ROOT if root is None else root
    security = base / "security"
    return (
        security / "aegis-policy.json",
        security / "aegis-policy.sig",
        security / "aegis-verify.pub",
    )


def load_policy(root: Path | None = None) -> tuple[dict, str]:
    """Verify and parse the signed Aegis policy."""
    policy_path, signature_path, public_path = policy_paths(root)

    raw = policy_path.read_bytes()
    if len(raw) > MAX_POLICY_BYTES:
        raise AegisError("aegis policy exceeds size limit")
    signature = signature_path.read_bytes()
    if len(signature) != 64:
        raise AegisError("aegis policy signature has wrong length")

    # Imported lazily so `status` remains usable on minimal Python installs.
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    public_key = Ed25519PublicKey.from_public_bytes(_root_public_key())
    try:
        public_key.verify(signature, raw)
    except (InvalidSignature, ValueError) as exc:
        raise AegisError("aegis policy signature invalid") from exc

    try:
        disk_key = public_path.read_bytes()
    except OSError as exc:
        raise AegisError("aegis public key unavailable") from exc
    if disk_key != _root_public_key():
        raise AegisError("aegis public key mismatch")

    try:
        policy = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise AegisError("aegis policy is not valid JSON") from exc
    if not isinstance(policy, dict) or policy.get("schema") != POLICY_SCHEMA:
        raise AegisError("unsupported aegis policy schema")

    anchors = policy.get("anchors")
    if not isinstance(anchors, dict) or not anchors:
        raise AegisError("aegis policy contains no anchors")
    for name, digest in anchors.items():
        if not isinstance(name, str) or not isinstance(digest, str):
            raise AegisError("invalid aegis anchor entry")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise AegisError("invalid aegis anchor digest")
        parts = Path(name).parts
        if Path(name).is_absolute() or ".." in parts or not parts:
            raise AegisError("unsafe aegis anchor path")
    if not isinstance(policy.get("rules"), dict):
        raise AegisError("aegis policy rules missing")

    return policy, _sha256_bytes(raw)


def audit(policy: dict, root: Path | None = None) -> list[str]:
    """Return the relative paths whose current bytes disagree with the policy."""
    base = ROOT if root is None else root
    failures: list[str] = []
    for name, expected in policy["anchors"].items():
        target = base / name
        try:
            actual = None
            if target.is_file() and not target.is_symlink():
                actual = sha256_file(target)
        except OSError:
            actual = None
        if actual != expected:
            failures.append(name)
    return failures


def verdict(root: Path | None = None) -> dict:
    """Compute a verdict without ever raising to the caller."""
    try:
        policy, digest = load_policy(root)
        failures = audit(policy, root)
        return {
            "ok": not failures,
            "policy_digest": digest,
            "failures": failures,
            "reason": "anchor-mismatch" if failures else "",
            "policy": policy,
        }
    except Exception as exc:  # fail closed, but keep the reason opaque by default
        return {
            "ok": False,
            "policy_digest": None,
            "failures": ["<policy-unavailable>"],
            "reason": type(exc).__name__,
            "policy": None,
        }


def report(result: dict) -> None:
    """Print a deliberately low-information message on the untrusted path."""
    if result["ok"]:
        return
    if os.environ.get("PARALLAX_AEGIS_STRICT") == "1":
        print(
            "AEGIS: untrusted bootstrap ({}: {})".format(
                result["reason"], ", ".join(result["failures"])
            ),
            file=sys.stderr,
        )
    else:
        print("ERROR: protection profile unavailable (aegis/0x7B)", file=sys.stderr)


def manifest_block(result: dict, operation: str) -> dict:
    """Trust block embedded in every generated protection manifest."""
    return {
        "schema": BLOCK_SCHEMA,
        "operation": operation,
        "verdict": "trusted" if result["ok"] else "quarantine",
        "policy_digest": result["policy_digest"],
        "canary": secrets.token_hex(16),
        "enforced_at_utc": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
        "anchor_failure_count": 0 if result["ok"] else len(result["failures"]),
    }


def assert_protected_manifest(manifest: dict, result: dict) -> None:
    """Reject artifacts whose trust block or protected policy flags changed."""
    if not result["ok"]:
        raise AegisError("local protection profile is not trusted")
    block = manifest.get("aegis")
    if not isinstance(block, dict):
        raise AegisError("manifest is missing the aegis trust block")
    if block.get("schema") != BLOCK_SCHEMA:
        raise AegisError("unsupported aegis trust block")
    if block.get("verdict") != "trusted":
        raise AegisError("artifact is quarantined by aegis")
    canary = block.get("canary")
    if not isinstance(canary, str) or not re.fullmatch(r"[0-9a-f]{32,128}", canary):
        raise AegisError("aegis canary is missing or malformed")
    expected_digest = result["policy_digest"]
    if expected_digest and block.get("policy_digest") != expected_digest:
        raise AegisError("aegis policy digest changed since protection")

    rules = (result.get("policy") or {}).get("rules", {})
    required_flags = rules.get("required_protection_flags", {})
    if not isinstance(required_flags, dict):
        raise AegisError("aegis required protection flags are malformed")
    protection = manifest.get("protection")
    if not isinstance(protection, dict):
        raise AegisError("manifest protection block missing")
    for name, expected in required_flags.items():
        if protection.get(name) != expected:
            raise AegisError(f"protected policy flag changed: {name}")

    allowlist = rules.get("packer_sha256_allowlist", [])
    if isinstance(allowlist, list) and allowlist:
        packer = manifest.get("packer")
        if not isinstance(packer, dict) or packer.get("sha256") not in allowlist:
            raise AegisError("packer is not in the signed allowlist")


def _status_payload(result: dict) -> dict:
    return {
        "ok": result["ok"],
        "policy_digest": result["policy_digest"],
        "reason": result["reason"],
        "failures": result["failures"],
    }


def main(argv: list[str] | None = None) -> int:
    commands = {"status", "enforce"}
    args = sys.argv[1:] if argv is None else list(argv)
    if len(args) != 1 or args[0] not in commands:
        print(f"usage: {Path(__file__).name} {{{'|'.join(sorted(commands))}}}", file=sys.stderr)
        return 2
    result = verdict()
    if args[0] == "status":
        print(json.dumps(_status_payload(result), sort_keys=True))
    elif args[0] == "enforce":
        report(result)
    return 0 if result["ok"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
