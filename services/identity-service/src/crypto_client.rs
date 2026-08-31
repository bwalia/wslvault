//! Wrapping and unwrapping via the crypto-service.
//!
//! identity-service needs somewhere safe to keep the private half of each
//! tenant's token signing key. Storing it under a key from its own environment
//! would recreate exactly the problem the seal exists to solve — key material
//! whose custody is a plaintext environment variable.
//!
//! So it delegates to the crypto-service, which puts signing keys under the
//! root KEK and therefore under the seal. The useful consequence: a sealed
//! vault cannot unwrap a signing key, so it cannot mint tokens. That is correct
//! behaviour, and it comes for free rather than needing a check of its own.

use tracing::warn;

pub mod crypto_proto {
    tonic::include_proto!("wslvault.crypto.v1");
}

use crypto_proto::crypto_service_client::CryptoServiceClient;

/// Thin client over a shared, lazily-connected channel.
#[derive(Clone)]
pub struct CryptoClient {
    channel: tonic::transport::Channel,
}

impl CryptoClient {
    /// # Panics
    /// If `endpoint` is not a valid URI — a startup-time configuration error.
    pub fn new(endpoint: &str) -> Self {
        let channel = wslvault_core::grpc_channel::lazy_channel(endpoint)
            .unwrap_or_else(|e| panic!("crypto-service endpoint is unusable: {e}"));
        Self { channel }
    }

    /// Encrypt `plaintext` under `tenant_id`'s key hierarchy.
    ///
    /// Returns `"<dek_id>:<ciphertext_b64>"`, the convention the crypto-service
    /// decrypt path expects back.
    pub async fn wrap(
        &self,
        tenant_id: String,
        plaintext: &[u8],
        aad: Vec<u8>,
    ) -> Result<String, String> {
        let mut client = CryptoServiceClient::new(self.channel.clone());
        let resp = client
            .encrypt(crypto_proto::EncryptRequest {
                tenant_id,
                plaintext: plaintext.to_vec(),
                aad,
            })
            .await
            .map_err(|e| {
                warn!(error = %e, "crypto-service wrap failed");
                describe(&e)
            })?
            .into_inner();

        Ok(format!("{}:{}", resp.dek_id, resp.ciphertext_b64))
    }

    /// Reverse of [`wrap`].
    pub async fn unwrap(
        &self,
        tenant_id: String,
        wrapped: &str,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        let mut client = CryptoServiceClient::new(self.channel.clone());
        let resp = client
            .decrypt(crypto_proto::DecryptRequest {
                tenant_id,
                ciphertext_b64: wrapped.to_string(),
                aad,
            })
            .await
            .map_err(|e| {
                warn!(error = %e, "crypto-service unwrap failed");
                describe(&e)
            })?
            .into_inner();

        Ok(resp.plaintext)
    }
}

/// Turn a transport failure into something an operator can act on.
///
/// A sealed vault is the expected case here, not an error to bury: it means
/// somebody needs to run `sys/unseal`, and saying so beats "transport error".
fn describe(status: &tonic::Status) -> String {
    if status.code() == tonic::Code::Unavailable && status.message().contains("sealed") {
        return "vault is sealed: unseal it before issuing tokens".to_string();
    }
    format!("crypto-service: {}", status.message())
}
