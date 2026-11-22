# ParallaxLibPacker — threat model and limits

## What the protector actually guarantees

PVM4 ARM64 v3 protects a **client-side** ARM64 shared library. It raises the
cost of static patching, relocated-slot hooks and read-only segment edits,
and it terminates the process with `exit_group(137)` on confirmed protected-path
tampering (one-second watchdog).

It is **not** a mathematical guarantee and it is not an anti-cheat or DRM
authority. The native runtime is distributed as a binary-only artifact in this
repository; source-level "fixes" cannot change its internal algorithms.

## Non-fixable by a compiled-library-only protector

These are inherent limits, not bugs:

- **Runtime memory dumps.** The original library is never written back to
  disk, but a hooked or root process can still read mapped memory.
- **Fully compromised runtime.** Root, kernel modules, debugger or an
  injected loader can observe and modify anything the process sees.
- **Watchdog interval.** Detection happens on a one-second tick; there is a
  bounded window between checks.
- **Application/server logic.** The packer cannot invent certificate pins,
  API response signatures or entitlement checks. Those belong to the app
  and its server.
- **Key compromise.** A leaked Ed25519 provenance key or APK signing key
  invalidates the provenance/identity guarantees.

## Actionable hardening checklist

1. Always use a **fresh CI-built packer** from the GitHub Release and verify
   its SHA-256 (the frontend records the packer hash in the manifest).
2. Generate a dedicated Ed25519 provenance keypair per product and keep
   `signing.key` outside source control. Verify every artifact with
   `parallax_ultra.py verify --require-signature` before shipping.
3. If the final APK uses API 24+ with a v2/v3 signing block, enable
   `--apk-cert-sha256` with the **app signing** certificate DER SHA-256
   (`apksigner verify --print-certs`). Test split/base APK installs first.
4. Use Self-Trust Ultra only around your own deliberate hooks:
   `begin()` ... `end()`. Never call `grant_all()` in production code.
5. Keep critical license/entitlement decisions on a signed server response.
   Treat client-side checks as a speed bump, not the authority.
6. Test the protected library on real ARM64 devices with the exact target
   APK and signing certificate before release; a wrong pin fails closed.

## Platform note

`parallax_ultra.py` now supports Android/Termux filesystems that do not
implement `os.link`. Publication still uses an exclusive create and never
overwrites an existing destination.
