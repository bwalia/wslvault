//! Axum middleware layer for automatic HTTP metrics collection.
//!
//! Wraps every HTTP request and records duration and status in the
//! Prometheus metric families defined in `collector`.

use std::time::Instant;

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

use super::collector::{HTTP_REQUESTS_TOTAL, HTTP_REQUEST_DURATION};

/// Axum middleware that records HTTP request duration and count.
///
/// Usage:
/// ```ignore
/// use axum::middleware;
/// let app = Router::new()
///     .route("/foo", get(handler))
///     .layer(middleware::from_fn(metrics_middleware));
/// ```
pub async fn metrics_middleware(request: Request, next: Next) -> Response {
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let service = std::env::var("VAULT_SERVICE_NAME").unwrap_or_else(|_| "unknown".into());

    let start = Instant::now();
    let response = next.run(request).await;
    let duration = start.elapsed().as_secs_f64();

    let status = response.status().as_u16().to_string();

    // Normalise paths to avoid cardinality explosion:
    // Replace UUIDs and numeric IDs with placeholders.
    let normalised_path = normalise_path(&path);

    HTTP_REQUEST_DURATION
        .with_label_values(&[&method, &normalised_path, &status, &service])
        .observe(duration);

    HTTP_REQUESTS_TOTAL
        .with_label_values(&[&method, &normalised_path, &status, &service])
        .inc();

    response
}

/// Replace path segments that look like IDs with `:id` to keep metric cardinality bounded.
fn normalise_path(path: &str) -> String {
    path.split('/')
        .map(|segment| {
            if segment.is_empty() {
                segment.to_string()
            } else if segment.len() >= 20 || is_uuid_like(segment) || segment.parse::<u64>().is_ok()
            {
                ":id".to_string()
            } else {
                segment.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Check if a path segment looks like a UUID (8-4-4-4-12 hex pattern).
fn is_uuid_like(s: &str) -> bool {
    s.len() == 36
        && s.chars().enumerate().all(|(i, c)| {
            if i == 8 || i == 13 || i == 18 || i == 23 {
                c == '-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalise_static_path() {
        assert_eq!(normalise_path("/v1/secret/data"), "/v1/secret/data");
    }

    #[test]
    fn normalise_uuid_path() {
        assert_eq!(
            normalise_path("/v1/secret/data/550e8400-e29b-41d4-a716-446655440000"),
            "/v1/secret/data/:id"
        );
    }

    #[test]
    fn normalise_numeric_id() {
        assert_eq!(normalise_path("/v1/leases/12345"), "/v1/leases/:id");
    }
}
