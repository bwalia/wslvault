//! HA clustering primitives for WSLVault.
//!
//! Provides leader election via PostgreSQL advisory locks, node registration
//! and heartbeat tracking, and cluster configuration. No external infrastructure
//! dependencies beyond the existing PostgreSQL database.

pub mod config;
pub mod error;
pub mod leader;
pub mod node;
pub mod store;
