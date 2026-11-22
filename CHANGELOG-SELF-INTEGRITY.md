# Crash Fix and Self-Integrity Hardening

Date: 2026-10-30

## Root causes addressed

1. Load-time root, tracer, LD_PRELOAD, and process-map checks could reject
   otherwise compatible applications before constructors or JNI initialization.
2. Foreign libc/curl/TLS function prologues were hashed and classified as
   hostile when Dobby, ShadowHook, vendor instrumentation, or a legitimate
   application hook had already installed a trampoline.
3. The periodic watchdog repeated process-wide framework scans and forced
   whole-process termination on ambiguous environmental signals.
4. The protection manifest and README described the old global-scanning policy,
   making generated metadata inaccurate.

## Implemented changes

- Runtime precheck is now compatibility-only and initializes optional foreign
  owner ranges without scanning the environment.
- Relocation protection is scoped to GOT/PLT slots owned by the protected
  module; foreign function entry bytes are not baselined.
- Read-only PT_LOAD hashing remains active for protected code and read-only
  security data after relocation.
- Independent runtime verifier code hashes remain active.
- Dobby, ShadowHook, injected-module names, root state, debugger state,
  LD_PRELOAD, and unrelated mappings are ignored.
- Binary-only strict mode terminates with `exit_group(137)` after confirmed protected-image, protected-slot, or critical imported-target tampering.
- Constructor and explicit self-trust windows continue to support authorized
  mutations made by the protected library.
- Generated manifests report the strict binary-only scope and termination response.
- Retired the unused legacy assembly stub that contained destructive failure actions; accidental compilation now stops with a build-time error.
- Added static regression tests that fail if process-wide scans, foreign
  prologue checks, or forced exits are reintroduced into the active path.

## Compatibility policy

The active Ultra profile supports ARM64/AArch64 ELF64 ET_DYN libraries accepted
by the existing frontend validator. Unsupported or malformed ELF input is
rejected before publication. Rooted and non-rooted runtime environments are not
distinguished by the active integrity policy.

## Verification status

The source-policy regression is wired into GitHub Actions. A full cross-build,
stub regeneration, QEMU ARM64 smoke test, Dobby compatibility smoke test, and
self-trust smoke test must complete in CI before merge.

No physical Android device matrix was executed in this editing environment.
Device/manufacturer/Android-version compatibility is therefore not claimed
until corresponding APK load tests and tombstone-free smoke tests are run.

## Strict binary-only extension

With no C/C++ source changes available, synchronous per-operation gates cannot be inserted. The strict runtime therefore adds one-second watchdog enforcement, critical libc/curl/TLS owner validation, and 32-byte prologue baselines while continuing to ignore unrelated framework/module presence. This materially raises runtime URL/libc hook resistance but does not provide a zero-race or unbreakable guarantee.

## Startup crash compatibility fix

Strict owner/prologue verification no longer rejects an OEM, application, Dobby, or ShadowHook trampoline that already exists when the protected library loads. A clean trusted target receives prologue monitoring; an existing trampoline receives a slot-only baseline. Protected slot replacement, protected image patching, and post-baseline changes still terminate with exit_group(137). Environment range collection is advisory and can no longer abort startup.
