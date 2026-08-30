//! wslvault-storage: PostgreSQL persistence layer for the WSLVault platform.
//!
//! Provides typed query wrappers over sqlx, centralizing all database access.
//! Services import this crate instead of using sqlx directly.

pub mod api_key_store;
pub mod audit_store;
pub mod key_store;
pub mod lease_store;
pub mod policy_store;
pub mod pool;
pub mod quota_store;
pub mod schema_store;
pub mod secret_store;
pub mod tenant_store;
