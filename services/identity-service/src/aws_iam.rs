//! AWS IAM authentication via STS `GetCallerIdentity`.
//!
//! # Flow
//!
//! 1. The client signs an STS `GetCallerIdentity` request using its AWS
//!    credentials (SDK, instance profile, EKS IRSA, etc.).
//! 2. The signed request URL, body, and headers are sent to WSLVault.
//! 3. This module replays the signed request against the real STS endpoint.
//! 4. STS returns the caller's Account, ARN, and UserId — confirming the
//!    caller possesses valid AWS credentials.
//! 5. Optionally, the ARN is compared against a list of bound IAM roles
//!    to restrict which identities may authenticate.
//!
//! This is the same approach used by HashiCorp Vault's `aws` auth method.

use std::collections::HashMap;

use tracing::info;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the AWS IAM auth backend.
#[derive(Debug, Clone)]
pub struct AwsIamConfig {
    /// STS endpoint (default: `https://sts.amazonaws.com`).
    pub sts_endpoint: String,

    /// Mapping from AWS account ID → wslvault tenant_id.
    /// If empty, the caller must supply `tenant_id` explicitly in the
    /// authentication request and it will not be cross-checked against the
    /// account.
    pub account_tenant_map: HashMap<String, String>,

    /// Default policies assigned to AWS IAM principals.
    pub default_policies: Vec<String>,

    /// Optional list of allowed IAM role ARN patterns (glob).
    /// An empty list means all ARNs are accepted.
    pub bound_iam_role_arns: Vec<String>,

    /// HTTP client timeout for the STS replay call.
    pub sts_timeout_seconds: u64,
}

impl Default for AwsIamConfig {
    fn default() -> Self {
        Self {
            sts_endpoint: "https://sts.amazonaws.com".to_string(),
            account_tenant_map: HashMap::new(),
            default_policies: Vec::new(),
            bound_iam_role_arns: Vec::new(),
            sts_timeout_seconds: 10,
        }
    }
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

/// Validates AWS IAM identities by replaying signed STS requests.
pub struct AwsIamManager {
    config: AwsIamConfig,
    http_client: reqwest::Client,
}

/// The result of a successful AWS IAM authentication.
#[derive(Debug, Clone)]
pub struct AwsIamValidationResult {
    /// AWS account ID.
    pub account_id: String,
    /// Full IAM ARN (e.g. `arn:aws:iam::123456789012:role/my-role`).
    pub arn: String,
    /// STS UserId field (role session name for assumed roles).
    #[allow(dead_code)]
    pub user_id: String,
    /// Resolved wslvault tenant_id.
    pub tenant_id: String,
    /// Policies assigned to this identity.
    pub policies: Vec<String>,
    /// Display name derived from the ARN.
    pub display_name: String,
}

#[allow(dead_code)] // wire/DTO type: fields exist for serde and validation, not direct reads
/// Errors from AWS IAM authentication.
#[derive(Debug, thiserror::Error)]
pub enum AwsIamError {
    #[error("STS request failed: {0}")]
    StsRequestFailed(String),

    #[error("STS returned non-200: {status} — {body}")]
    StsNonSuccess { status: u16, body: String },

    #[error("failed to parse STS response: {0}")]
    ParseError(String),

    #[error("IAM role ARN '{arn}' is not in the bound roles list")]
    UnboundRole { arn: String },

    #[error("cannot resolve tenant for AWS account '{account_id}'")]
    #[allow(dead_code)]
    UnmappedAccount { account_id: String },

    #[error("missing required header: {0}")]
    MissingHeader(String),

    #[error("invalid request URL: {0}")]
    InvalidUrl(String),

    #[error("failed to build HTTP client for AWS IAM: {0}")]
    HttpClientBuild(String),
}

impl AwsIamManager {
    /// Builds a manager, returning an error if the HTTP client cannot be
    /// constructed (e.g. invalid TLS backend). Fails startup cleanly rather
    /// than panicking the process from within a constructor.
    pub fn new(config: AwsIamConfig) -> Result<Self, AwsIamError> {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.sts_timeout_seconds))
            .build()
            .map_err(|e| AwsIamError::HttpClientBuild(e.to_string()))?;

        Ok(Self {
            config,
            http_client,
        })
    }

    /// Validates an AWS IAM identity by replaying the signed STS request.
    ///
    /// # Arguments
    ///
    /// * `iam_request_url` — The STS URL (must be `https://sts.amazonaws.com/`)
    /// * `iam_request_body` — Base64-encoded POST body
    /// * `iam_request_headers_json` — JSON-encoded `HashMap<String, String>` of
    ///   signed headers
    /// * `bound_role_arn` — Optional: if non-empty, the STS ARN must match
    /// * `claimed_tenant_id` — The tenant_id from the auth request
    pub async fn validate(
        &self,
        iam_request_url: &str,
        iam_request_body: &str,
        iam_request_headers_json: &str,
        bound_role_arn: &str,
        claimed_tenant_id: &str,
    ) -> Result<AwsIamValidationResult, AwsIamError> {
        // Validate the URL points to STS to prevent SSRF.
        if !iam_request_url.starts_with("https://sts.amazonaws.com")
            && !iam_request_url.starts_with("https://sts.")
        {
            return Err(AwsIamError::InvalidUrl(format!(
                "URL must point to AWS STS: {iam_request_url}"
            )));
        }

        // Decode the body from base64.
        let body_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, iam_request_body)
                .map_err(|e| AwsIamError::ParseError(format!("base64 decode body: {e}")))?;

        // Parse the signed headers.
        let headers: HashMap<String, String> = serde_json::from_str(iam_request_headers_json)
            .map_err(|e| AwsIamError::ParseError(format!("parse headers JSON: {e}")))?;

        // Replay the signed request to STS.
        let mut request_builder = self.http_client.post(iam_request_url).body(body_bytes);

        for (key, value) in &headers {
            request_builder = request_builder.header(key.as_str(), value.as_str());
        }

        let sts_response = request_builder
            .send()
            .await
            .map_err(|e| AwsIamError::StsRequestFailed(e.to_string()))?;

        let status = sts_response.status().as_u16();
        let response_text = sts_response
            .text()
            .await
            .map_err(|e| AwsIamError::StsRequestFailed(format!("read response body: {e}")))?;

        if status != 200 {
            return Err(AwsIamError::StsNonSuccess {
                status,
                body: response_text,
            });
        }

        // Parse the STS XML response.
        // STS returns XML like:
        // <GetCallerIdentityResponse>
        //   <GetCallerIdentityResult>
        //     <Arn>arn:aws:iam::123456789012:role/my-role</Arn>
        //     <UserId>AROAEXAMPLE:session-name</UserId>
        //     <Account>123456789012</Account>
        //   </GetCallerIdentityResult>
        // </GetCallerIdentityResponse>
        let identity = parse_sts_response(&response_text)?;

        info!(
            account_id = %identity.account,
            arn = %identity.arn,
            user_id = %identity.user_id,
            "AWS IAM identity verified via STS"
        );

        // Check bound role ARN if specified.
        if !bound_role_arn.is_empty() && identity.arn != bound_role_arn {
            return Err(AwsIamError::UnboundRole {
                arn: identity.arn.clone(),
            });
        }

        // Check against configured bound ARN patterns.
        if !self.config.bound_iam_role_arns.is_empty() {
            let arn_allowed = self
                .config
                .bound_iam_role_arns
                .iter()
                .any(|pattern| arn_matches(pattern, &identity.arn));

            if !arn_allowed {
                return Err(AwsIamError::UnboundRole {
                    arn: identity.arn.clone(),
                });
            }
        }

        // Resolve tenant_id: prefer account mapping, fall back to claimed.
        let tenant_id = self
            .config
            .account_tenant_map
            .get(&identity.account)
            .cloned()
            .unwrap_or_else(|| claimed_tenant_id.to_string());

        // Derive display name from the ARN.
        let display_name = identity
            .arn
            .rsplit('/')
            .next()
            .unwrap_or(&identity.arn)
            .to_string();

        Ok(AwsIamValidationResult {
            account_id: identity.account,
            arn: identity.arn,
            user_id: identity.user_id,
            tenant_id,
            policies: self.config.default_policies.clone(),
            display_name,
        })
    }
}

// ---------------------------------------------------------------------------
// STS response parsing
// ---------------------------------------------------------------------------

struct StsIdentity {
    arn: String,
    user_id: String,
    account: String,
}

/// Parses the XML response from STS `GetCallerIdentity`.
///
/// Uses simple string scanning instead of a full XML parser to avoid adding
/// a dependency.  The STS response format is well-defined and stable.
fn parse_sts_response(xml: &str) -> Result<StsIdentity, AwsIamError> {
    let arn = extract_xml_tag(xml, "Arn")
        .ok_or_else(|| AwsIamError::ParseError("missing <Arn> in STS response".into()))?;
    let user_id = extract_xml_tag(xml, "UserId")
        .ok_or_else(|| AwsIamError::ParseError("missing <UserId> in STS response".into()))?;
    let account = extract_xml_tag(xml, "Account")
        .ok_or_else(|| AwsIamError::ParseError("missing <Account> in STS response".into()))?;

    Ok(StsIdentity {
        arn,
        user_id,
        account,
    })
}

/// Extracts the text content of a simple XML element: `<Tag>content</Tag>`.
fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].trim().to_string())
}

/// Simple glob-style ARN matching.
/// Supports `*` as a wildcard anywhere in the pattern.
fn arn_matches(pattern: &str, arn: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return arn.starts_with(prefix);
    }
    pattern == arn
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sts_response_valid_xml() {
        let xml = r#"
        <GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
          <GetCallerIdentityResult>
            <Arn>arn:aws:iam::123456789012:role/my-role</Arn>
            <UserId>AROAEXAMPLE:session-name</UserId>
            <Account>123456789012</Account>
          </GetCallerIdentityResult>
        </GetCallerIdentityResponse>
        "#;

        let identity = parse_sts_response(xml).unwrap();
        assert_eq!(identity.arn, "arn:aws:iam::123456789012:role/my-role");
        assert_eq!(identity.user_id, "AROAEXAMPLE:session-name");
        assert_eq!(identity.account, "123456789012");
    }

    #[test]
    fn parse_sts_response_missing_arn_returns_error() {
        let xml = "<GetCallerIdentityResponse><GetCallerIdentityResult><UserId>x</UserId><Account>y</Account></GetCallerIdentityResult></GetCallerIdentityResponse>";
        assert!(parse_sts_response(xml).is_err());
    }

    #[test]
    fn arn_matches_exact() {
        assert!(arn_matches(
            "arn:aws:iam::123456789012:role/my-role",
            "arn:aws:iam::123456789012:role/my-role"
        ));
        assert!(!arn_matches(
            "arn:aws:iam::123456789012:role/my-role",
            "arn:aws:iam::123456789012:role/other"
        ));
    }

    #[test]
    fn arn_matches_wildcard_suffix() {
        assert!(arn_matches(
            "arn:aws:iam::123456789012:role/*",
            "arn:aws:iam::123456789012:role/anything"
        ));
        assert!(!arn_matches(
            "arn:aws:iam::123456789012:role/*",
            "arn:aws:iam::999999999999:role/anything"
        ));
    }

    #[test]
    fn arn_matches_star_matches_all() {
        assert!(arn_matches("*", "arn:aws:iam::123:role/x"));
    }
}
