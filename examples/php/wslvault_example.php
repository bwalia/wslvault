<?php
/**
 * WSLVault Secret Lifecycle Example — PHP 8.0+
 *
 * Shows the full flow:
 *   1. Write a secret (base64-encoded payload)
 *   2. Read the secret back and decode it
 *   3. List secrets
 *   4. Read a specific version
 *   5. Soft-delete a version
 *   6. (Optional) Exchange an API key for a JWT via /v1/auth/api-key
 *
 * Usage:
 *   VAULT_ADDR=http://localhost:8081 \
 *   VAULT_TENANT_ID=019d813d-74bc-7660-89a7-f02fd9f2736d \
 *   php wslvault_example.php
 *
 * Prerequisites: PHP extension ext-curl (standard in most PHP builds)
 */

declare(strict_types=1);

const SECRET_PATH = 'demo/php/smtp-credentials';

/** Return an env variable or a default value. */
function envOrDefault(string $name, string $default): string
{
    $val = getenv($name);
    return ($val !== false && $val !== '') ? $val : $default;
}

$vaultAddr   = envOrDefault('VAULT_ADDR', 'http://localhost:8081');
$identityAddr = envOrDefault('VAULT_IDENTITY_ADDR', 'http://localhost:18082');
$tenantId    = envOrDefault('VAULT_TENANT_ID', '019d813d-74bc-7660-89a7-f02fd9f2736d');
$principalId = envOrDefault('VAULT_PRINCIPAL_ID', 'php-example');
$policies    = envOrDefault('VAULT_POLICIES', 'admin');

/**
 * Send an authenticated HTTP request to WSLVault and return the decoded JSON body.
 *
 * In production the gateway injects X-Principal-Id / X-Policies from the JWT.
 * When calling the secret-engine directly (dev / service mesh), pass them manually.
 *
 * @param  string                   $method      HTTP method (GET, POST, …)
 * @param  string                   $url         Full URL
 * @param  array<string,mixed>|null $body        Payload to JSON-encode, or null for no body
 * @param  string                   $tenantId
 * @param  string                   $principalId
 * @param  string                   $policies
 * @return array<string,mixed>
 */
function vaultRequest(
    string $method,
    string $url,
    ?array $body,
    string $tenantId,
    string $principalId,
    string $policies
): array {
    $ch = curl_init($url);
    if ($ch === false) {
        throw new RuntimeException("curl_init failed for {$url}");
    }

    $headers = [
        'Content-Type: application/json',
        "X-Tenant-Id: {$tenantId}",
        "X-Principal-Id: {$principalId}",
        "X-Policies: {$policies}",
    ];

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CUSTOMREQUEST  => $method,
        CURLOPT_HTTPHEADER     => $headers,
        CURLOPT_FAILONERROR    => false,
    ]);

    if ($body !== null) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body, JSON_THROW_ON_ERROR));
    }

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    curl_close($ch);

    if ($response === false) {
        throw new RuntimeException("curl error: {$curlError}");
    }

    if ($httpCode < 200 || $httpCode >= 300) {
        throw new RuntimeException("{$method} {$url} failed: HTTP {$httpCode} — {$response}");
    }

    if ($response === '') {
        return [];
    }

    return json_decode($response, true, 512, JSON_THROW_ON_ERROR);
}

/*
 * Optional: exchange an API key for a short-lived JWT.
 *
 * function exchangeApiKey(string $identityAddr, string $apiKey, string $tenantId): string {
 *     $ch = curl_init("{$identityAddr}/v1/auth/api-key");
 *     curl_setopt_array($ch, [
 *         CURLOPT_RETURNTRANSFER => true,
 *         CURLOPT_POST           => true,
 *         CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
 *         CURLOPT_POSTFIELDS     => json_encode([
 *             'api_key'   => $apiKey,
 *             'tenant_id' => $tenantId,
 *         ]),
 *     ]);
 *     $body = json_decode(curl_exec($ch), true);
 *     curl_close($ch);
 *     return $body['token']; // Use as: Authorization: Bearer <token>
 * }
 */

try {
    // ── 1. Write a secret ──────────────────────────────────────────────────────
    echo "==> 1. Writing secret to '" . SECRET_PATH . "'...\n";
    $payload = json_encode([
        'smtp_host'     => 'smtp.example.com',
        'smtp_user'     => 'noreply@example.com',
        'smtp_password' => 'mail-p@ssw0rd',
    ], JSON_THROW_ON_ERROR);
    $data = base64_encode($payload);

    $writeResp = vaultRequest(
        'POST',
        "{$vaultAddr}/v1/secret/data/" . SECRET_PATH,
        ['data' => $data],
        $tenantId, $principalId, $policies
    );
    echo "    secret_id={$writeResp['secret_id']}  version={$writeResp['version']}\n";
    $version = $writeResp['version'];

    // ── 2. Read the secret back ────────────────────────────────────────────────
    echo "\n==> 2. Reading secret from '" . SECRET_PATH . "'...\n";
    $readResp = vaultRequest(
        'GET',
        "{$vaultAddr}/v1/secret/data/" . SECRET_PATH,
        null,
        $tenantId, $principalId, $policies
    );
    $decoded = base64_decode($readResp['data']);
    echo "    Decoded: {$decoded}\n";

    // ── 3. List secrets ────────────────────────────────────────────────────────
    echo "\n==> 3. Listing secrets...\n";
    $listResp = vaultRequest(
        'GET',
        "{$vaultAddr}/v1/secret/list",
        null,
        $tenantId, $principalId, $policies
    );
    echo '    Secrets: ' . json_encode($listResp, JSON_PRETTY_PRINT) . "\n";

    // ── 4. Read a specific version ─────────────────────────────────────────────
    echo "\n==> 4. Reading version {$version} explicitly...\n";
    $verResp = vaultRequest(
        'GET',
        "{$vaultAddr}/v1/secret/data/" . SECRET_PATH . "?version={$version}",
        null,
        $tenantId, $principalId, $policies
    );
    echo "    version={$verResp['version']}  created_at={$verResp['created_at']}\n";

    // ── 5. Soft-delete the version ─────────────────────────────────────────────
    echo "\n==> 5. Soft-deleting version {$version}...\n";
    vaultRequest(
        'POST',
        "{$vaultAddr}/v1/secret/delete/" . SECRET_PATH,
        ['versions' => [$version]],
        $tenantId, $principalId, $policies
    );
    echo "    Deleted (soft — data retained for undelete).\n";

    echo "\nDone! All WSLVault operations completed successfully.\n";

} catch (Throwable $e) {
    fwrite(STDERR, "ERROR: {$e->getMessage()}\n");
    exit(1);
}
