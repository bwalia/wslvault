// WSLVault Secret Lifecycle Example — Java 11+
//
// Shows the full flow:
//   1. Write a secret (base64-encoded payload)
//   2. Read the secret back and decode it
//   3. List secrets
//   4. Read a specific version
//   5. Soft-delete a version
//   6. (Optional) Exchange an API key for a JWT via /v1/auth/api-key
//
// Compile & run (no external dependencies — uses java.net.http):
//   javac WslVaultExample.java && java WslVaultExample
//
// Environment variables (all optional, defaults shown):
//   VAULT_ADDR=http://localhost:8081
//   VAULT_TENANT_ID=019d813d-74bc-7660-89a7-f02fd9f2736d
//   VAULT_PRINCIPAL_ID=java-example
//   VAULT_POLICIES=admin

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class WslVaultExample {

    private static final String VAULT_ADDR =
        getEnvOrDefault("VAULT_ADDR", "http://localhost:8081");
    private static final String IDENTITY_ADDR =
        getEnvOrDefault("VAULT_IDENTITY_ADDR", "http://localhost:18082");
    private static final String TENANT_ID =
        getEnvOrDefault("VAULT_TENANT_ID", "019d813d-74bc-7660-89a7-f02fd9f2736d");
    private static final String PRINCIPAL_ID =
        getEnvOrDefault("VAULT_PRINCIPAL_ID", "java-example");
    private static final String POLICIES =
        getEnvOrDefault("VAULT_POLICIES", "admin");
    private static final String SECRET_PATH = "demo/java/oauth-credentials";

    private final HttpClient http;

    public WslVaultExample() {
        this.http = HttpClient.newHttpClient();
    }

    /**
     * Send an HTTP request with the WSLVault headers and return the response body.
     *
     * In production the gateway injects X-Principal-Id / X-Policies from the JWT.
     * When calling the secret-engine directly (dev / service mesh), pass them manually.
     */
    private String send(String method, String url, String jsonBody) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .header("Content-Type", "application/json")
            .header("X-Tenant-Id", TENANT_ID)
            .header("X-Principal-Id", PRINCIPAL_ID)
            .header("X-Policies", POLICIES);

        if (jsonBody != null) {
            builder.method(method, BodyPublishers.ofString(jsonBody));
        } else {
            builder.method(method, BodyPublishers.noBody());
        }

        HttpResponse<String> resp = http.send(builder.build(), BodyHandlers.ofString());
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            throw new RuntimeException(
                method + " " + url + " failed: HTTP " + resp.statusCode() + " — " + resp.body()
            );
        }
        return resp.body();
    }

    /*
     * Optional: exchange an API key for a short-lived JWT.
     *
     * String exchangeApiKey(String apiKey) throws Exception {
     *     String body = "{\"api_key\":\"" + apiKey + "\",\"tenant_id\":\"" + TENANT_ID + "\"}";
     *     HttpRequest req = HttpRequest.newBuilder()
     *         .uri(URI.create(IDENTITY_ADDR + "/v1/auth/api-key"))
     *         .header("Content-Type", "application/json")
     *         .POST(BodyPublishers.ofString(body))
     *         .build();
     *     HttpResponse<String> resp = http.send(req, BodyHandlers.ofString());
     *     return jsonString(resp.body(), "token"); // use as: Bearer <token>
     * }
     */

    // ── Minimal JSON helpers (no external library) ────────────────────────────

    /** Extract a quoted string value from a flat JSON object by key. */
    private static String jsonString(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]+)\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }

    /** Extract an integer value from a flat JSON object by key. */
    private static int jsonInt(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*(\\d+)").matcher(json);
        return m.find() ? Integer.parseInt(m.group(1)) : -1;
    }

    public void run() throws Exception {

        // ── 1. Write a secret ──────────────────────────────────────────────────
        System.out.println("==> 1. Writing secret to '" + SECRET_PATH + "'...");
        String payload = "{\"client_id\":\"app-12345\",\"client_secret\":\"sup3r-s3cr3t\",\"scope\":\"openid profile\"}";
        String data = Base64.getEncoder().encodeToString(payload.getBytes());
        String writeBody = String.format("{\"data\":\"%s\"}", data);

        String writeRespBody = send("POST", VAULT_ADDR + "/v1/secret/data/" + SECRET_PATH, writeBody);
        String secretId = jsonString(writeRespBody, "secret_id");
        int version = jsonInt(writeRespBody, "version");
        System.out.println("    secret_id=" + secretId + "  version=" + version);

        // ── 2. Read the secret back ────────────────────────────────────────────
        System.out.println("\n==> 2. Reading secret from '" + SECRET_PATH + "'...");
        String readRespBody = send("GET", VAULT_ADDR + "/v1/secret/data/" + SECRET_PATH, null);
        String encodedData = jsonString(readRespBody, "data");
        String decoded = new String(Base64.getDecoder().decode(encodedData));
        System.out.println("    Decoded: " + decoded);

        // ── 3. List secrets ────────────────────────────────────────────────────
        System.out.println("\n==> 3. Listing secrets...");
        String listRespBody = send("GET", VAULT_ADDR + "/v1/secret/list", null);
        System.out.println("    Secrets: " + listRespBody);

        // ── 4. Read a specific version ─────────────────────────────────────────
        System.out.println("\n==> 4. Reading version " + version + " explicitly...");
        String verRespBody = send("GET",
            VAULT_ADDR + "/v1/secret/data/" + SECRET_PATH + "?version=" + version, null);
        System.out.println("    version=" + jsonInt(verRespBody, "version")
            + "  created_at=" + jsonString(verRespBody, "created_at"));

        // ── 5. Soft-delete the version ─────────────────────────────────────────
        System.out.println("\n==> 5. Soft-deleting version " + version + "...");
        String deleteBody = String.format("{\"versions\":[%d]}", version);
        send("POST", VAULT_ADDR + "/v1/secret/delete/" + SECRET_PATH, deleteBody);
        System.out.println("    Deleted (soft — data retained for undelete).");

        System.out.println("\nDone! All WSLVault operations completed successfully.");
    }

    public static void main(String[] args) {
        try {
            new WslVaultExample().run();
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            System.exit(1);
        }
    }

    private static String getEnvOrDefault(String name, String defaultValue) {
        String val = System.getenv(name);
        return (val != null && !val.isEmpty()) ? val : defaultValue;
    }
}
