//! Pluggable authentication-method backends for the identity-service.
//!
//! Each sub-module exposes an independent manager + HTTP router that can be
//! wired into the main axum application in `main.rs`.  Managers are optional
//! at runtime: when the relevant environment variable is not set the feature
//! is simply omitted from the router, matching the pattern used by
//! `aws_iam`, `azure_workload`, and `oidc`.

pub mod kubernetes;
pub mod ldap;
pub mod oauth_device;
