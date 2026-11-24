<?php
declare(strict_types=1);

/**
 * Server-side example for ParallaxSignedEndpoint.java (Aegis profile).
 *
 * Requirements:
 *   - PHP 8.1+ with ext-sodium
 *   - PARALLAX_ED25519_SECRET_KEY_FILE points to a file OUTSIDE the web root.
 *
 * Security properties:
 *   - every envelope is Ed25519-signed by the server, including a random canary;
 *   - nonces are single-use, so a captured response cannot be replayed;
 *   - device identity must come from an authenticated session hook;
 *   - every failure returns a well-formed DECOY envelope with the same JSON
 *     shape as a real one. A patched client thinks it succeeded, but the URL
 *     is an unresolvable .invalid canary host and the event is logged.
 *
 * Integrate this into your authenticated license/session endpoint. Do not
 * expose it as an unauthenticated standalone signer.
 */

header('Content-Type: application/json; charset=utf-8');

const ENDPOINT_URL = 'https://parallaxloadersdk.parallaxserver.online/connect.php';
const DECOY_URL = 'https://parallax-canary.invalid/quarantine';
const TTL_SECONDS = 120;
const NONCE_MIN_BYTES = 16;
const NONCE_MAX_BYTES = 256;
const DEVICE_MAX_BYTES = 256;

/** Uniform, low-information security event. Never log raw secrets or tokens. */
function aegis_log(string $event, string $canary, string $detail = ''): void
{
    $payload = [
        'event' => $event,
        'canary' => $canary,
        'detail' => $detail,
        'at' => gmdate('c'),
    ];
    error_log('PARALLAX_AEGIS ' . json_encode($payload, JSON_UNESCAPED_SLASHES));
}

/** Exact byte layout shared with ParallaxSignedEndpoint.canonicalize(). */
function aegis_canonical(
    string $version,
    string $expiresAt,
    string $deviceId,
    string $nonce,
    string $url,
    string $canary,
    string $degraded
): string {
    return $version . "\n"
        . $expiresAt . "\n"
        . $deviceId . "\n"
        . $nonce . "\n"
        . $url . "\n"
        . $canary . "\n"
        . $degraded;
}

/** @param array<string,string> $envelope */
function aegis_sign(array $envelope, string $secretKey): array
{
    $canonical = aegis_canonical(
        $envelope['version'],
        $envelope['expires_at'],
        $envelope['device_id'],
        $envelope['nonce'],
        $envelope['url'],
        $envelope['canary'],
        $envelope['degraded']
    );
    $envelope['signature'] = base64_encode(
        sodium_crypto_sign_detached($canonical, $secretKey)
    );
    return $envelope;
}

/** @param array<string,string> $envelope */
function aegis_emit(array $envelope): never
{
    echo json_encode($envelope, JSON_UNESCAPED_SLASHES);
    exit;
}

/**
 * The decoy is a valid signed envelope, so a client that patched out local
 * verification still accepts it. Its URL never resolves and its canary ties
 * the attempt to a server-side log entry.
 */
function aegis_quarantine(string $reason, string $deviceId, string $nonce, string $secretKey): never
{
    $canary = bin2hex(random_bytes(16));
    aegis_log('quarantine', $canary, $reason);

    aegis_emit(aegis_sign([
        'status' => 'success',
        'version' => (string) floor(microtime(true) * 1000),
        'expires_at' => (string) (time() + TTL_SECONDS),
        'device_id' => $deviceId,
        'nonce' => $nonce,
        'url' => DECOY_URL,
        'canary' => $canary,
        'degraded' => '1',
    ], $secretKey));
}

/** Exclusive-create nonce cache. Returns false on replay or cache failure. */
function aegis_nonce_fresh(string $nonce, string $deviceId): bool
{
    $dir = getenv('PARALLAX_AEGIS_CACHE_DIR');
    if ($dir === false || $dir === '') {
        $dir = sys_get_temp_dir() . '/parallax-aegis';
    }
    if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
        return false;
    }

    $key = hash('sha256', $deviceId . "\n" . $nonce);
    $path = $dir . '/' . $key . '.nonce';
    $handle = @fopen($path, 'xb');
    if ($handle === false) {
        return false;
    }
    fwrite($handle, (string) time());
    fclose($handle);

    // Best-effort garbage collection; never affects the request verdict.
    if (random_int(1, 64) === 1) {
        $cutoff = time() - 3600;
        foreach (glob($dir . '/*.nonce') ?: [] as $old) {
            if (filemtime($old) !== false && filemtime($old) < $cutoff) {
                @unlink($old);
            }
        }
    }
    return true;
}

/* ---------------------------------------------------------------- bootstrap */

if (!extension_loaded('sodium')) {
    http_response_code(503);
    echo json_encode(['status' => 'error', 'message' => 'Server crypto unavailable'], JSON_UNESCAPED_SLASHES);
    exit;
}

$keyFile = getenv('PARALLAX_ED25519_SECRET_KEY_FILE');
if ($keyFile === false || $keyFile === '' || !is_readable($keyFile)) {
    http_response_code(503);
    echo json_encode(['status' => 'error', 'message' => 'Signing key unavailable'], JSON_UNESCAPED_SLASHES);
    exit;
}

$keyText = trim((string) file_get_contents($keyFile));
try {
    $secretKey = sodium_base642bin($keyText, SODIUM_BASE64_VARIANT_ORIGINAL);
} catch (Throwable $e) {
    http_response_code(503);
    echo json_encode(['status' => 'error', 'message' => 'Signing key malformed'], JSON_UNESCAPED_SLASHES);
    exit;
}
if (strlen($secretKey) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
    http_response_code(503);
    echo json_encode(['status' => 'error', 'message' => 'Signing key has wrong size'], JSON_UNESCAPED_SLASHES);
    exit;
}

/* ------------------------------------------------------------------ request */

$postedDevice = isset($_POST['device_id']) ? trim((string) $_POST['device_id']) : '';
$nonce = isset($_POST['nonce']) ? trim((string) $_POST['nonce']) : '';
$deviceId = $postedDevice;

// Clamp echoed fields so a decoy can never be used as a reflection primitive.
if (strlen($deviceId) > DEVICE_MAX_BYTES) {
    $deviceId = substr($deviceId, 0, DEVICE_MAX_BYTES);
}
if (strlen($nonce) > NONCE_MAX_BYTES) {
    $nonce = substr($nonce, 0, NONCE_MAX_BYTES);
}

if (
    $postedDevice === ''
    || strlen($postedDevice) > DEVICE_MAX_BYTES
    || strlen($nonce) < NONCE_MIN_BYTES
) {
    aegis_quarantine('invalid-request', $deviceId, $nonce, $secretKey);
}

// An integrator supplies this hook and returns e.g.
// ['active' => true, 'device_id' => '...', 'license' => 'active'].
// Without it the hardened profile fails closed into decoy mode.
$requireSession = getenv('PARALLAX_AEGIS_REQUIRE_SESSION') !== '0';
if ($requireSession) {
    $session = function_exists('parallax_aegis_resolve_session')
        ? parallax_aegis_resolve_session()
        : null;
    if (!is_array($session) || empty($session['active'])) {
        aegis_quarantine('session-missing', $deviceId, $nonce, $secretKey);
    }
    $sessionDevice = isset($session['device_id']) ? (string) $session['device_id'] : '';
    if ($sessionDevice === '' || !hash_equals($sessionDevice, $postedDevice)) {
        aegis_quarantine('device-mismatch', $deviceId, $nonce, $secretKey);
    }
    if (isset($session['license']) && $session['license'] !== 'active') {
        aegis_quarantine('license-inactive', $deviceId, $nonce, $secretKey);
    }
}

if (!aegis_nonce_fresh($nonce, $deviceId)) {
    aegis_quarantine('nonce-replay', $deviceId, $nonce, $secretKey);
}

$canary = bin2hex(random_bytes(16));
$expiresAt = (string) (time() + TTL_SECONDS);
$version = (string) floor(microtime(true) * 1000);

aegis_log('envelope-issued', $canary, 'ok');

aegis_emit(aegis_sign([
    'status' => 'success',
    'version' => $version,
    'expires_at' => $expiresAt,
    'device_id' => $deviceId,
    'nonce' => $nonce,
    'url' => ENDPOINT_URL,
    'canary' => $canary,
    'degraded' => '0',
], $secretKey));
