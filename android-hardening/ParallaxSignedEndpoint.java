import android.util.Base64;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Locale;

/**
 * Defensive endpoint guard for Android SDKs (Aegis profile).
 *
 * The server signs: version + expiry + deviceId + nonce + url + canary +
 * degraded flag. A URL/string replacement, a replayed response, or a patched
 * local verifier therefore cannot produce a usable real endpoint:
 *
 *  - replacing the URL invalidates the signature;
 *  - replaying a nonce makes the server return a signed decoy envelope;
 *  - a patched verifier that accepts decoys talks to a .invalid canary host.
 *
 * Requires an Android/JCA provider with Ed25519 support (API 28+ on modern
 * Android builds). Replace PUBLIC_KEY_X509_B64 with the Base64 X.509 Subject
 * Public Key Info for your Ed25519 public key.
 */
public final class ParallaxSignedEndpoint {
    private static final String EXPECTED_HOST = "parallaxloadersdk.parallaxserver.online";
    private static final String PUBLIC_KEY_X509_B64 =
            "REPLACE_WITH_YOUR_ED25519_X509_PUBLIC_KEY_BASE64";

    // Keep endpoint envelopes short lived to make replay less useful.
    private static final long MAX_FUTURE_TTL_SECONDS = 5 * 60L;

    private ParallaxSignedEndpoint() {}

    /**
     * Legacy overload for old five-field signers. New Aegis responses must be
     * passed through the seven-field overload below, otherwise the signature
     * cannot be reconstructed.
     */
    public static URI verifyAndGetUri(
            String url,
            long version,
            long expiresAtEpochSeconds,
            String deviceId,
            String nonce,
            String signatureB64) throws Exception {
        return verifyAndGetUri(
                url, version, expiresAtEpochSeconds, deviceId, nonce, "", false, signatureB64);
    }

    /** Verify a full Aegis endpoint envelope and return the exact signed URI. */
    public static URI verifyAndGetUri(
            String url,
            long version,
            long expiresAtEpochSeconds,
            String deviceId,
            String nonce,
            String canary,
            boolean degraded,
            String signatureB64) throws Exception {

        if (url == null || deviceId == null || nonce == null || canary == null || signatureB64 == null) {
            throw new SecurityException("Missing signed endpoint field");
        }

        // A decoy is a *validly signed* envelope. It must be rejected here so
        // an unpatched client never uses it; a patched client is redirected to
        // an unresolvable canary host and leaks the canary in its DNS traffic.
        if (degraded) {
            throw new SecurityException("Endpoint envelope is degraded");
        }
        if (!canary.matches("[0-9a-fA-F]{32,128}")) {
            throw new SecurityException("Endpoint canary is missing or malformed");
        }

        final long now = System.currentTimeMillis() / 1000L;
        if (expiresAtEpochSeconds <= now) {
            throw new SecurityException("Signed endpoint expired");
        }
        if (expiresAtEpochSeconds - now > MAX_FUTURE_TTL_SECONDS) {
            throw new SecurityException("Signed endpoint TTL too large");
        }
        if (version <= 0L) {
            throw new SecurityException("Invalid endpoint version");
        }

        final URI uri = URI.create(url);
        validateUri(uri);

        final String canonical = canonicalize(
                version,
                expiresAtEpochSeconds,
                deviceId,
                nonce,
                url,
                canary,
                degraded);

        final PublicKey publicKey = loadPublicKey();
        final Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(publicKey);
        verifier.update(canonical.getBytes(StandardCharsets.UTF_8));

        final byte[] signature = Base64.decode(signatureB64, Base64.NO_WRAP);
        if (!verifier.verify(signature)) {
            throw new SecurityException("Endpoint signature invalid");
        }

        // Return the exact URI that was covered by the signature. Do not
        // re-create it from a mutable global/static URL after verification.
        return uri;
    }

    /** Legacy five-field canonicalization. */
    public static String canonicalize(
            long version,
            long expiresAtEpochSeconds,
            String deviceId,
            String nonce,
            String url) {
        return canonicalize(version, expiresAtEpochSeconds, deviceId, nonce, url, "", false);
    }

    /** Exact byte layout shared with EndpointEnvelopeSigner.php. */
    public static String canonicalize(
            long version,
            long expiresAtEpochSeconds,
            String deviceId,
            String nonce,
            String url,
            String canary,
            boolean degraded) {
        return Long.toString(version) + "\n"
                + Long.toString(expiresAtEpochSeconds) + "\n"
                + deviceId + "\n"
                + nonce + "\n"
                + url + "\n"
                + canary + "\n"
                + (degraded ? "1" : "0");
    }

    private static void validateUri(URI uri) {
        if (uri == null) {
            throw new SecurityException("Invalid endpoint URI");
        }

        final String scheme = uri.getScheme();
        final String host = uri.getHost();

        if (scheme == null || !"https".equals(scheme.toLowerCase(Locale.US))) {
            throw new SecurityException("HTTPS required");
        }
        if (host == null || !EXPECTED_HOST.equals(host.toLowerCase(Locale.US))) {
            throw new SecurityException("Unexpected endpoint host");
        }
        // Defence in depth: never allow a quarantine/canary host even if a
        // future signing bug made such an envelope appear valid.
        if (host.toLowerCase(Locale.US).endsWith(".invalid")) {
            throw new SecurityException("Quarantine host rejected");
        }
        if (uri.getUserInfo() != null) {
            throw new SecurityException("Endpoint userinfo not allowed");
        }
        if (uri.getFragment() != null) {
            throw new SecurityException("Endpoint fragment not allowed");
        }

        final int port = uri.getPort();
        if (port != -1 && port != 443) {
            throw new SecurityException("Unexpected endpoint port");
        }
    }

    private static PublicKey loadPublicKey() throws Exception {
        if (PUBLIC_KEY_X509_B64.startsWith("REPLACE_")) {
            throw new IllegalStateException("Configure Ed25519 public key first");
        }

        final byte[] encoded = Base64.decode(PUBLIC_KEY_X509_B64, Base64.DEFAULT);
        final X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);
        return KeyFactory.getInstance("Ed25519").generatePublic(spec);
    }
}
