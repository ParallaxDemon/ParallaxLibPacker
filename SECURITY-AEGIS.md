# Parallax Aegis — anti-patch trust chain

Aegis adds a second, independent trust layer around the existing PVM4 ARM64
protector. It does **not** change the binary-only runtime; it makes patches to
the toolchain and to the endpoint flow *ineffective* instead of merely hard.

## Trust chain

```text
Ed25519 root private key (NOT in this repository)
        |
        v  signs
security/aegis-policy.json  -- pins SHA-256 of every security-critical file
        |
        +--> scripts/parallax_aegis.py          (embedded root public key)
        +--> scripts/parallax_ultra.py          (protect/verify enforcement)
        +--> scripts/parallax-secure-pack.sh    (independent shell preflight)
        +--> android-hardening/EndpointEnvelopeSigner.php
        +--> android-hardening/ParallaxSignedEndpoint.java
        +--> .github/workflows/*.yml           (CI enforcement)
```

The policy signature is checked with the root public key that is embedded in
`parallax_aegis.py` **and** stored in `security/aegis-verify.pub`. Replacing one
copy breaks the other check, so a simple in-place edit cannot silently create a
new trusted baseline.

## Patch response matrix

| What an attacker changes | What happens |
| --- | --- |
| Patches `parallax_ultra.py` to skip checks | Anchor mismatch; generated manifest gets `aegis.verdict = quarantine`; `verify` refuses the artifact. The tool still prints a normal success line. |
| Replaces `aegis-policy.json` | Ed25519 signature check fails; frontend fails closed into quarantine. |
| Replaces the embedded root public key | The edited module's own hash no longer matches the signed policy. |
| Removes the Aegis call from the wrapper | CI enforces `parallax_aegis.py enforce` and the test suite; branch protection must be enabled on `main`. |
| Patches the Android client verifier out | Server still enforces session/device binding and single-use nonces; a replay or unauthenticated call returns a signed decoy envelope. |
| Replays a captured envelope | Nonce cache rejects it and returns a `.invalid` canary URL with a new canary. |
| Edits the manifest to restore `trusted` | `verify` checks the signed policy digest, required protection flags and the canary format. |

The deliberate design choice is **quiet quarantine**, not a loud "tamper
detected" banner. A patched tool keeps producing plausible output, but nothing
it produces can pass `parallax_ultra.py verify` or CI. Set
`PARALLAX_AEGIS_STRICT=1` when *you* need verbose anchor diagnostics.

## Server endpoint profile

`EndpointEnvelopeSigner.php` now requires:

1. `PARALLAX_ED25519_SECRET_KEY_FILE` — 64-byte base64 Ed25519 secret key outside the web root.
2. `parallax_aegis_resolve_session()` — an integration hook returning
   `['active' => true, 'device_id' => '...', 'license' => 'active']`.
   Without the hook the profile fails closed. For local development only, set
   `PARALLAX_AEGIS_REQUIRE_SESSION=0`.
3. `PARALLAX_AEGIS_CACHE_DIR` — optional writable directory for the nonce cache.

Every envelope is signed over seven newline-separated fields:

```text
version
expires_at
device_id
nonce
url
canary
degraded        # "0" real, "1" decoy
```

`ParallaxSignedEndpoint.java` must be updated to the seven-field overload. It
rejects `degraded = 1`, malformed canaries and `*.invalid` hosts before checking
the signature. A client patched to ignore those checks will follow the decoy
URL to `https://parallax-canary.invalid/quarantine`; the canary in that request
links the attempt to a server log entry.

## Operations

```sh
# Diagnostics (never exposes details in default mode)
python3 scripts/parallax_aegis.py status
PARALLAX_AEGIS_STRICT=1 python3 scripts/parallax_aegis.py status

# CI gate: 0 = trusted, 3 = untrusted
python3 scripts/parallax_aegis.py enforce
```

### Rotating the root key and anchors

The root private key must be generated and stored outside the repository:

```sh
python3 - <<'PY'
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
k = Ed25519PrivateKey.generate()
open('/secure/path/aegis-root.key','wb').write(k.private_bytes_raw())
open('security/aegis-verify.pub','wb').write(k.public_key().public_bytes_raw())
print(k.public_key().public_bytes_raw().hex())   # paste into ROOT_PUBLIC_KEY_HEX
PY
```

Then update `ROOT_PUBLIC_KEY_HEX` in `scripts/parallax_aegis.py`, recompute every
entry in `security/aegis-policy.json`, and re-sign the policy:

```sh
python3 - <<'PY'
import hashlib, json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
p = Path('security/aegis-policy.json')
policy = json.loads(p.read_text())
for name in policy['anchors']:
    policy['anchors'][name] = hashlib.sha256(Path(name).read_bytes()).hexdigest()
raw = (json.dumps(policy, sort_keys=True, indent=2) + '\n').encode()
p.write_bytes(raw)
key = Ed25519PrivateKey.from_private_bytes(Path('/secure/path/aegis-root.key').read_bytes())
Path('security/aegis-policy.sig').write_bytes(key.sign(raw))
PY
```

Re-run the full test suite after any rotation. Note that a policy digest change
invalidates manifests created under the previous policy by design.

## Limits

* A compiled-library-only protector still cannot make runtime memory dumps,
  kernel-level hooking or a rooted device mathematically impossible. This
  layer protects the toolchain and the server authority, not those physics.
* Anyone with write access to the repository *and* the root signing key can
  mint a new trusted baseline. Protect the key, and enable branch protection /
  required CI checks on `main`.
* The decoy URL is intentionally unresolvable. It must not be used for legitimate
  traffic; clients never see it unless the server is rejecting a request.
