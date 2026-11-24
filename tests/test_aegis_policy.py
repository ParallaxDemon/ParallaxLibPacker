#!/usr/bin/env python3
"""Regression checks for the Aegis anti-patch trust chain."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


aegis = load_module("parallax_aegis", SCRIPTS / "parallax_aegis.py")
ultra = load_module("parallax_ultra", SCRIPTS / "parallax_ultra.py")


class AegisPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy, cls.digest = aegis.load_policy()

    def test_root_key_is_configured_and_matches_disk_copy(self) -> None:
        self.assertRegex(aegis.ROOT_PUBLIC_KEY_HEX, r"^[0-9a-fA-F]{64}$")
        self.assertNotIn("REPLACE", aegis.ROOT_PUBLIC_KEY_HEX)
        _, _, public_path = aegis.policy_paths()
        self.assertEqual(public_path.read_bytes(), bytes.fromhex(aegis.ROOT_PUBLIC_KEY_HEX))

    def test_signed_policy_anchors_match_checked_in_files(self) -> None:
        self.assertEqual(aegis.audit(self.policy, ROOT), [])
        self.assertRegex(self.digest, r"^[0-9a-f]{64}$")

    def test_hardening_rules_are_enabled(self) -> None:
        rules = self.policy["rules"]
        self.assertTrue(rules["require_manifest_aegis_block"])
        self.assertTrue(rules["reject_quarantine_on_verify"])
        self.assertTrue(rules["decoy_on_tamper"])
        self.assertTrue(rules["require_session_binding"])
        self.assertGreaterEqual(rules["nonce_replay_cache_ttl_seconds"], 60)
        flags = rules["required_protection_flags"]
        self.assertTrue(flags["aegis_signed_self_integrity"])
        self.assertFalse(flags["standard_restore_command_exposed"])
        self.assertTrue(flags["parallax_watchdog"])

    def test_tampered_anchor_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in self.policy["anchors"]:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / name, target)
            for name in ("aegis-policy.json", "aegis-policy.sig", "aegis-verify.pub"):
                shutil.copy2(ROOT / "security" / name, root / "security" / name)

            clean = aegis.verdict(root=root)
            self.assertTrue(clean["ok"], clean)

            patched = root / "scripts" / "parallax_ultra.py"
            patched.write_text(patched.read_text() + "\n# patched\n")
            dirty = aegis.verdict(root=root)
            self.assertFalse(dirty["ok"])
            self.assertIn("scripts/parallax_ultra.py", dirty["failures"])

    def test_quarantine_block_is_rejected_by_verify_path(self) -> None:
        trusted = {
            "ok": True,
            "policy_digest": self.digest,
            "failures": [],
            "reason": "",
            "policy": self.policy,
        }
        untrusted = dict(trusted, ok=False, failures=["scripts/parallax_ultra.py"])
        required = self.policy["rules"]["required_protection_flags"]

        manifest = {
            "protection": dict(required),
            "packer": {"sha256": "0" * 64},
            "aegis": aegis.manifest_block(trusted, "protect"),
        }
        aegis.assert_protected_manifest(manifest, trusted)

        bad = json.loads(json.dumps(manifest))
        bad["aegis"] = aegis.manifest_block(untrusted, "protect")
        with self.assertRaises(aegis.AegisError):
            aegis.assert_protected_manifest(bad, trusted)

        bad = json.loads(json.dumps(manifest))
        bad["aegis"].pop("canary")
        with self.assertRaises(aegis.AegisError):
            aegis.assert_protected_manifest(bad, trusted)

        bad = json.loads(json.dumps(manifest))
        bad["protection"]["standard_restore_command_exposed"] = True
        with self.assertRaises(aegis.AegisError):
            aegis.assert_protected_manifest(bad, trusted)

        with self.assertRaises(aegis.AegisError):
            aegis.assert_protected_manifest(manifest, untrusted)


class AegisIntegrationTest(unittest.TestCase):
    def test_frontend_wires_aegis_into_protect_and_verify(self) -> None:
        source = (SCRIPTS / "parallax_ultra.py").read_text()
        for needle in (
            "import parallax_aegis as aegis",
            "aegis.manifest_block(current_verdict(), \"protect\")",
            "aegis.assert_protected_manifest(manifest, current_verdict())",
            "aegis.report(current_verdict())",
            '"aegis_signed_self_integrity": True',
        ):
            self.assertIn(needle, source)

    def test_wrapper_runs_independent_preflight(self) -> None:
        source = (SCRIPTS / "parallax-secure-pack.sh").read_text()
        self.assertIn("parallax_aegis.py", source)
        self.assertIn(" enforce ", source)

    def test_client_only_wrapper_enforces_all_four_controls(self) -> None:
        wrapper = SCRIPTS / "parallax-client-only.sh"
        source = wrapper.read_text()
        for needle in (
            "PARALLAX_APK_CERT_SHA256",
            'parallax_aegis.py" enforce',
            "--signing-key",
            "--apk-cert-sha256",
            "--require-signature",
            "Client-only hardened profile: COMPLETE",
        ):
            self.assertIn(needle, source)
        if os.name == "posix":
            self.assertEqual(
                subprocess.run(["bash", "-n", str(wrapper)], capture_output=True).returncode,
                0,
            )

    def test_php_signer_has_replay_binding_and_decoy(self) -> None:
        source = (ROOT / "android-hardening" / "EndpointEnvelopeSigner.php").read_text()
        for needle in (
            "function aegis_quarantine(",
            "function aegis_nonce_fresh(",
            "hash_equals($sessionDevice, $postedDevice)",
            "PARALLAX_AEGIS_REQUIRE_SESSION",
            "https://parallax-canary.invalid/quarantine",
            "'degraded' => '1'",
            "'canary' => $canary",
        ):
            self.assertIn(needle, source)

    def test_java_verifier_rejects_decoys(self) -> None:
        source = (ROOT / "android-hardening" / "ParallaxSignedEndpoint.java").read_text()
        for needle in (
            "if (degraded) {",
            'canary.matches("[0-9a-fA-F]{32,128}")',
            'endsWith(".invalid")',
            "boolean degraded) {",
            '(degraded ? "1" : "0")',
        ):
            self.assertIn(needle, source)

    @unittest.skipIf(os.name == "nt", "fake packer uses a POSIX shell script")
    def test_patched_frontend_still_outputs_only_quarantined_artifacts(self) -> None:
        policy, _ = aegis.load_policy()
        original_root = aegis.ROOT
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in policy["anchors"]:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / name, target)
            for name in ("aegis-policy.json", "aegis-policy.sig", "aegis-verify.pub"):
                shutil.copy2(ROOT / "security" / name, root / "security" / name)

            # Simulate a patch that removes a security check.
            patched = root / "scripts" / "parallax_ultra.py"
            patched.write_text(patched.read_text() + "\n# patched\n", encoding="utf-8")

            ident = bytearray(16)
            ident[:4] = b"\x7fELF"
            ident[4], ident[5], ident[6] = 2, 1, 1
            header = bytes(ident) + struct.pack(
                "<HHIQQQIHHHHHH", 3, 183, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0
            )
            load = struct.pack("<IIQQQQQQ", 1, 5, 176, 0x1000, 0x1000, 32, 32, 4096)
            stack = struct.pack("<IIQQQQQQ", 0x6474E551, 6, 0, 0, 0, 0, 0, 16)
            source = root / "lib.so"
            source.write_bytes(header + load + stack + os.urandom(64))

            packer = root / "fake_packer.sh"
            packer.write_text('#!/bin/sh\ncp "$4" "$3"\nprintf X >> "$3"\n')
            packer.chmod(0o700)

            # The frontend keeps its own imported aegis module instance when
            # both modules are loaded by path, so patch that one as well.
            aegis.ROOT = root
            ultra.aegis.ROOT = root
            ultra.reset_verdict()
            try:
                args = argparse.Namespace(
                    input=str(source),
                    output=str(root / "out.so"),
                    packer=str(packer),
                    apk_cert_sha256=None,
                    unsigned_dev=True,
                    signing_key=None,
                    preserve_size=False,
                )
                ultra.protect(args)
                manifest = json.loads((root / "out.so.pvm.json").read_text())
                self.assertEqual(manifest["aegis"]["verdict"], "quarantine")
            finally:
                aegis.ROOT = original_root
                ultra.aegis.ROOT = original_root
                ultra.reset_verdict()


if __name__ == "__main__":
    unittest.main()
