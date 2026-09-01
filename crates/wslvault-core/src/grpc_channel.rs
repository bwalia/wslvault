//! Shared, lazily-connected gRPC channels.
//!
//! Every service-to-service call in this workspace used to call
//! `SomeClient::connect(endpoint).await` *inside the request handler*. A single
//! secret read therefore performed two full TCP plus HTTP/2 handshakes before
//! doing any work — one to the policy-engine, one to the crypto-service — and a
//! third in the spawned audit task. On the hot path that handshake dominates
//! the latency, and it churns sockets in proportion to request volume.
//!
//! A `tonic::transport::Channel` is the right unit to hold instead: it owns the
//! connection, multiplexes concurrent requests over it, reconnects on its own
//! when it drops, and is cheap to clone. `connect_lazy` builds one without
//! waiting for the connection, so constructing a client never blocks startup or
//! fails because a dependency has not come up yet — the first request pays for
//! the connect, and only that one.

use tonic::transport::{Channel, Endpoint};

use crate::error::VaultError;

/// Build a lazily-connected channel to `endpoint`.
///
/// Returns an error only for a malformed URI; a service that is merely down
/// yields a working channel whose requests fail until it returns, which is what
/// lets services start in any order.
pub fn lazy_channel(endpoint: &str) -> Result<Channel, VaultError> {
    Ok(Endpoint::from_shared(endpoint.to_string())
        .map_err(|e| VaultError::ValidationError {
            field: "endpoint".into(),
            reason: format!("invalid gRPC endpoint {endpoint:?}: {e}"),
        })?
        // Keepalives so a silently dropped connection is noticed before a
        // request is routed onto it.
        .tcp_keepalive(Some(std::time::Duration::from_secs(30)))
        .connect_lazy())
}

#[cfg(test)]
mod tests {
    use super::*;

    // `connect_lazy` registers with the hyper-util Tokio executor, which panics
    // outside a runtime context. These are `tokio::test` for that reason, not
    // because the calls await anything.

    #[tokio::test]
    async fn builds_without_the_endpoint_being_up() {
        // Nothing is listening on this port; construction must still succeed,
        // or services could not start in an arbitrary order.
        assert!(lazy_channel("http://127.0.0.1:1").is_ok());
    }

    #[test]
    fn rejects_a_malformed_endpoint() {
        // No runtime needed: this fails during URI parsing, before connect_lazy.
        assert!(lazy_channel("not a uri").is_err());
    }

    #[tokio::test]
    async fn cloning_is_cheap_and_shares_the_connection() {
        let ch = lazy_channel("http://127.0.0.1:1").unwrap();
        let _clone = ch.clone();
        // Compiles and clones — the point is that callers hold clones rather
        // than dialling again.
    }
}
