# ParallaxLibPacker — Ultra ARM64 Library Protection

Parallax Ultra is the hardened client-side protection profile for Android ARM64 shared libraries.

The canonical profile is **PVM4 ARM64 v3**. The protected artifact on disk is not a normal UPX-compatible compressed stream, and the runtime loader does not write the original shared library back to disk.

> Scope: client-side protection only. A protected library may continue to use its own HTTPS/API/server endpoints normally. Parallax Ultra does not rewrite, proxy, block, or depend on those network requests.

## Aegis anti-patch trust chain

Aegis is a signed self-integrity layer around the packer frontend and the
optional endpoint-signing example. It pins SHA-256 anchors for security-critical
files in an Ed25519-signed policy, and treats anchor failures as *quarantine*:
the patched tool still prints a normal success message, but the manifest it
produces is rejected by `verify` and CI. On the server side, single-use nonces,
session/device binding and signed canary envelopes make a captured or replayed
response useless; rejected requests receive a valid-looking decoy envelope
pointing at an unresolvable `.invalid` host.

See [SECURITY-AEGIS.md](SECURITY-AEGIS.md) for the trust chain, response matrix,
key rotation and operational limits.

## Client-only hardened profile (no server dependency)

Everything in this profile runs on the build host and the Android device. The
optional endpoint-signing example under `android-hardening/` is **not** used.

~~~sh
PARALLAX_PACKER=/path/to/fresh/parallax_linux \
PARALLAX_SIGNING_KEY=/secure/signing.key \
PARALLAX_VERIFY_KEY=/secure/verify.pub \
PARALLAX_APK_CERT_SHA256=<APP_SIGNING_CERT_SHA256> \
  ./scripts/parallax-client-only.sh libOriginal.so libProtected.so
~~~

The wrapper refuses to run unless all four controls are present, and fails
closed if any one is missing:

1. `parallax_aegis.py enforce` — signed anchors must be intact;
2. Ed25519-signed provenance manifest (no `--unsigned-dev`);
3. `--apk-cert-sha256` pin — a repackaged/resigned APK dies at startup;
4. `verify --require-signature` immediately after protection.

Manual equivalent:

~~~sh
python3 scripts/parallax_aegis.py enforce
python3 scripts/parallax_ultra.py protect libOriginal.so libProtected.so \
  --packer ./parallax-bin/parallax_linux \
  --signing-key ./parallax-keys/signing.key \
  --apk-cert-sha256 <APP_SIGNING_CERT_SHA256>
python3 scripts/parallax_ultra.py verify libProtected.so \
  --public-key ./parallax-keys/verify.pub --require-signature
~~~

**Client-only limit:** a rooted device, kernel hook or runtime memory dump
cannot be prevented by any code that ships inside the APK. This profile raises
the cost of static patching, URL/string edits and GOT hooks, and detects
tampering with `exit_group(137)` on a one-second watchdog tick. Treat it as
strong tamper resistance, not unbreakable DRM. Also keep branch protection on
`main`, otherwise the signed anchors themselves can be replaced in source.

## Security model

The active ARM64 runtime uses a binary-only strict policy:

- hashes file-backed read-only PT_LOAD ranges belonging to the protected
  library after decompression and relocation;
- baselines GLOB_DAT/JUMP_SLOT relocation slots owned by the protected module;
- uses 32-byte function-entry baselines for critical imported libc, curl,
  TLS, string, memory, DNS, socket and I/O targets only when the resolved
  target is safely verified in a clean trusted-owner range;
- protects independent runtime-integrity routines with separate code hashes;
- ignores root state, debugger presence, LD_PRELOAD and unrelated
  Dobby/ShadowHook/Frida module names;
- permits authorized constructor/JNI mutations through the self-trust window;
- immediately calls `exit_group(137)` after confirmed protected-path
  tampering.

The watchdog interval is one second. A compiled-library-only protector cannot
guarantee zero-time detection between ticks and cannot be mathematically
unbreakable; these checks raise bypass cost without making that claim.

Read-only URL/config patches and protected call-path redirection are covered.
The packer cannot invent application-specific certificate pins or response
signing keys. Those remain source/server integration responsibilities.

## Optional Android APK signing-certificate SHA-256 pin (Android 7+)

The optional flag pins the **SHA-256 fingerprint of the X.509 DER APK signing
certificate**, not the SHA-256 of the JKS keystore file or APK file. Run
apksigner verify --print-certs app-release.apk to extract the signer SHA-256.
For Play App Signing, use the Play **app signing** certificate, not upload key.

Protect directly (replace FINGERPRINT with 64 hex digits or colon-separated hex):

~~~sh
parallax_linux --parallax-ultra-lib --apk-cert-sha256 FINGERPRINT -o libProtected.so libOriginal.so
~~~

Via Python frontend:

~~~sh
python scripts/parallax_ultra.py protect libOriginal.so libProtected.so --packer ./parallax-bin/parallax_linux --signing-key ./parallax-keys/signing.key --apk-cert-sha256 FINGERPRINT
~~~

At startup the protected ARM64 loader locates its own installed APK from its
/proc/self/maps file mapping, parses APK Signing Block v2/v3/v3.1 and SHA-256
hashes signing certificate DER data. Every present recognized scheme/signer
must match. If unreadable or mismatched, it immediately terminates the entire
process with exit_group(137), *before* original constructors. No Java
PackageManager signature results are trusted.

The pinned profile accepts installed `/data/app/...` and adopted-storage
`/mnt/expand/<volume>/app/...` paths. It rejects a protected library loaded
from a writable folder alongside a copied signed `base.apk`. This restriction
applies only when `--apk-cert-sha256` is supplied; test the target device's
actual install path before enabling it.

**Important limits:** Android API 24+ with v2/v3 signing block and conventional
installed APK paths required. This is a signing-certificate identity check, NOT
independent validation of all APK bytes/signatures, and not a guarantee against
a fully compromised rooted/hooked runtime. APK installation-time verification
is performed by Android. Key rotation with multiple identities, alternate
loaders/paths, v1-only APKs, and Play-signed builds using a different signing
certificate can fail closed; test real split/base APK installs before enabling.
Without the flag the previous loader behavior is unchanged. Do not publish
private signing keys or private keystores.

## Self-Trust Ultra (opt-in)

The optional API lets code executing from the protected module authorize its
own deliberate code/data or relocation changes. Calls originating outside the
protected module are ignored.

ELF constructors receive an automatic trusted window. For later changes such
as hooks installed from JNI_OnLoad, use an explicit begin/end window:

~~~c
#include "include/parallax_selftrust.h"

static ParallaxSelfTrustApi *g_parallax;

__attribute__((visibility("default")))
void parallax_self_trust_init(ParallaxSelfTrustApi *api) {
    g_parallax = api;
}

void install_runtime_hooks(void) {
    g_parallax->begin(g_parallax->ctx);
    install_your_dobby_or_shadowhook_hooks();
    g_parallax->end(g_parallax->ctx);
}
~~~

`begin()` auto-seals if `end()` is forgotten. `grant_all()`,
`grant_slot()`, and `grant_range()` adopt an already-authorized mutation.
`trust_path()` remains in ABI v1 for backward compatibility but process-map
framework scanning is disabled by the self-only policy.

## Recommended commands

### 1. Install frontend dependency

~~~sh
python -m pip install -r scripts/requirements-secure.txt
~~~

### 2. Generate an Ed25519 provenance key

~~~sh
python scripts/parallax_ultra.py keygen ./parallax-keys
~~~

Keep parallax-keys/signing.key private and outside source control.

### 3. Protect an ARM64 Android library

Use the **CI-built packer from the GitHub Release** (`parallax-ultra-v3-latest`).

Host choice:

| Host | Asset | Notes |
| --- | --- | --- |
| Linux x86-64 | `parallax_linux` | Static; run on a PC/CI |
| Windows x86-64 | `ParallaxLibPacker-windows-x64.exe` | Run on Windows |
| Android ARM64 / Termux | `parallax_android_arm64` | Native bionic PIE, Android 7+ |
| Linux ARM64 | `parallax_linux_arm64` | aarch64 Linux / proot / chroot, not Android-native |

Linux x86-64:

~~~sh
gh release download parallax-ultra-v3-latest \
  --pattern 'parallax_linux*' --dir ./parallax-bin
~~~

Android/Termux native:

~~~sh
gh release download parallax-ultra-v3-latest \
  --pattern 'parallax_android_arm64*' --dir ~/parallax-bin
chmod +x ~/parallax-bin/parallax_android_arm64
~/parallax-bin/parallax_android_arm64 --version
~~~

The ultra runtime requires an input shared library that exports `DT_INIT`
(UPX's shared-library layout requirement). A library built without one needs a
small `_init` entry point, for example `void _init(void) {}` linked with
`-Wl,-init,_init`. Very small libraries can also be rejected as
`NotCompressibleException`; real app libraries are well above that threshold.

Termux always sets `LD_PRELOAD=libtermux-exec.so`, and the anti-hook guard
deliberately rejects `LD_PRELOAD`. When testing a protected library inside
Termux, unset it for the test process:

~~~sh
env -u LD_PRELOAD ./your-loader ./libProtected.so
~~~

Normal Android apps do not set `LD_PRELOAD`, so this workaround is only for
Termux-side testing.

The ARM64 runtime is `arm64-v8a` only. Protecting 32-bit `armeabi-v7a`
libraries would need a separate ARM32 ultra stub and is not supported by this
build.

Linux:

~~~sh
python scripts/parallax_ultra.py protect libOriginal.so libProtected.so \
  --packer ./parallax-bin/parallax_linux \
  --signing-key ./parallax-keys/signing.key
~~~

Windows:

~~~powershell
gh release download parallax-ultra-v3-latest `
  --pattern 'ParallaxLibPacker-windows-x64.exe*' --dir .\parallax-bin
python scripts/parallax_ultra.py protect libOriginal.so libProtected.so `
  --packer .\parallax-bin\ParallaxLibPacker-windows-x64.exe `
  --signing-key .\parallax-keys\signing.key
~~~

By default the frontend pads a smaller protected ELF with cryptographically random trailing bytes until its file size equals the original. If the protected ELF is larger than the original, exact-size mode fails instead of truncating data.

To allow a smaller output:

~~~sh
python scripts/parallax_ultra.py protect libOriginal.so libProtected.so \
  --packer /path/to/parallax_linux \
  --signing-key ./parallax-keys/signing.key \
  --no-preserve-size
~~~

### 4. Verify artifact and signed manifest

~~~sh
python scripts/parallax_ultra.py verify libProtected.so \
  --public-key ./parallax-keys/verify.pub \
  --require-signature
~~~

### 5. Shell wrapper

~~~sh
PARALLAX_PACKER=/path/to/parallax_linux \
PARALLAX_SIGNING_KEY=./parallax-keys/signing.key \
./scripts/parallax-secure-pack.sh libOriginal.so libProtected.so
~~~

Development-only unsigned output:

~~~sh
PARALLAX_PACKER=/path/to/parallax_linux \
PARALLAX_UNSIGNED_DEV=1 \
./scripts/parallax-secure-pack.sh libOriginal.so libProtected.so
~~~

### Low-level native command

~~~sh
parallax_linux --parallax-ultra-lib -o libProtected.so libOriginal.so
~~~

The old public Android selector and restore commands are not the Ultra interface:

~~~text
--android-shlib       removed from the public hardened interface
-d                    disabled
--decompress          disabled
--uncompress          disabled
~~~

There is deliberately no restore command for a PVM4-protected shared library.

## Runtime flow

~~~text
original ARM64 ELF
        |
        v
ELF validation + compression
        |
        v
PVM4 per-block lane selection
        |
        +--> stage A: stream transform
        +--> stage B: additive transform
        +--> stage C: bit-rotation transform
        +--> stage D: local permutation
        |
        v
non-standard protected block bytes on disk
        |
        v
loader startup hook checks
        |
        v
one private block copied + PVM4 inverse
        |
        v
native decompression into target PT_LOAD
        |
        v
transport block wiped
        |
        v
next block
~~~

The whole original shared library is not reconstructed as a filesystem file by the Ultra loader.

## Hook protection and API compatibility

The strict watchdog verifies:

1. protected-module GOT/PLT slot values;
2. critical imported libc/curl/TLS target ownership and entry prologues;
3. protected-module read-only executable/data hashes;
4. independent verifier-code hashes.

Unrelated framework presence is ignored. OEM/application trampolines already
present at startup are accepted as slot-only baselines so they cannot cause a
load-time false positive. After that baseline, replacing a protected relocation
slot, changing a safely monitored critical prologue, or patching protected
code/URL data causes immediate process termination.

Authorized mutations made by the protected library itself must occur during
the constructor/JNI startup window or an explicit self-trust window. Because
only a compiled `.so` is available, the packer cannot insert synchronous
verification before every individual network request; enforcement occurs at
startup and periodic watchdog checkpoints.

### Diagnostics

Pack-time validation rejects unsupported ELF class, byte order, architecture,
non-ET_DYN input, malformed program headers, RWX PT_LOAD, and executable
GNU_STACK. Internal loader failures retain distinct error codes. Compatibility
must still be verified using actual Android logcat/tombstones and a device
matrix; no 100% anti-hook claim is made.

## CI verification

The hardening branch verifies:

- PVM4 encode/decode vectors across lane tags;
- regeneration of the active ARM64 ELF-SO folded runtime;
- arm64-linux.shlib-init.S remains unchanged;
- Linux and Windows packer builds;
- RELRO / NX / no-RWX checks;
- a real AArch64 ET_DYN regression library importing strlen;
- actual protection with --parallax-ultra-lib;
- PVM4 tagging of compressed and literal ELF-SO blocks;
- protected ELF policy checks;
- public -d restoration must fail;
- qemu-user ARM64 runtime smoke: load, strlen, a watchdog window,
  and strlen again after the watchdog has fired;
- root-probe property matching is scoped to exact keys so unrelated
  `[ro.boot.*]: [disabled]` properties cannot trip it;
- Android NDK ARM64 (bionic PIE) packer build for native Termux use;
- Python manifest/key/ELF-policy tests;
- hardened ARM64 ELF-SO runtime regeneration with the Watchdog code compiled in;
- SHA-256 build artifacts.

## Important limit

No client-side native protector can make extraction mathematically impossible against an attacker who fully controls a rooted device. CPU instructions that execute eventually exist in executable form in memory.

PVM4 raises the cost of static extraction and removes the simple standard-packer-to-original-file recovery path. Every ELF-SO transport block (compressed and incompressible literal) is tagged and diversified; legacy untagged blocks are still accepted for compatibility. It also reduces decoded transport lifetime and adds hook/tamper checks.

Likewise, no in-process watchdog can survive an attacker who can patch the
watchdog itself. The Watchdog makes silent GOT/prologue/`.rodata` patching hard
and turns detected tampering into a silent whole-process exit. To keep the signal handler alive
after `DT_INIT`, the folded loader region is intentionally left mapped (in
memory only), so a protected library costs roughly one extra protected-image
worth of anonymous memory. Do not `dlclose()` a protected library while the
watchdog is active.

A future true function-level VM would require an ARM64 instruction lifter, custom IR, relocation/unwind/TLS support, and multiple interpreters. Current PVM4 is transport/runtime virtualization and is intentionally described accurately rather than as whole-program instruction virtualization.

## Legacy distribution packages

scripts/parallax_package.py and .plpkg are a separate signed/encrypted distribution format. They intentionally support authorized restoration and are not the runtime PVM4 protector.

See SECURE-PACKAGES.md.
