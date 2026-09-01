//! Transaction scopes that make PostgreSQL row-level security work.
//!
//! # Why this exists
//!
//! `004_multitenancy.sql` declared RLS policies keyed on the
//! `app.current_tenant_id` session variable, and nothing in the Rust tree ever
//! set it — a grep for the name returned only comments. The policies were
//! syntactically fine and matched nothing, so tenant isolation rested entirely
//! on every query remembering its own `WHERE tenant_id = $1`. That convention
//! held on the secret paths and did not hold everywhere: for one,
//! `shared.vault_confirm_rotation` resolves a rotation by id alone.
//!
//! This module is the missing half. A scope sets the variable that the policies
//! read, so the database enforces the boundary the application was enforcing
//! alone.
//!
//! # Why a transaction, and not the pool
//!
//! `SET LOCAL` reverts when the transaction ends. That matters more than it
//! looks: connections come from a shared pool and are handed to whichever
//! request needs one next. A plain `SET` would persist on the connection after
//! the request finished, and the next request to borrow it would inherit some
//! previous tenant's scope — which is the exact cross-tenant read this is
//! supposed to prevent, arriving through the mechanism meant to stop it. Scoped
//! to a transaction, a leak is impossible by construction.
//!
//! # Fail-closed
//!
//! `shared.rls_tenant_visible` (018) compares against
//! `current_setting('app.current_tenant_id', true)`, which is NULL when unset.
//! `tenant_id = NULL` is NULL, and RLS reads that as "not visible". So a query
//! that reaches the database outside a scope sees nothing rather than
//! everything. Forgetting to open a scope produces an empty result, not a
//! silent cross-tenant leak.

use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use wslvault_core::types::tenant::TenantId;
use wslvault_core::VaultError;

use crate::pool::DbPool;

/// A transaction bound to one tenant, or explicitly marked cross-tenant.
///
/// Obtain one from [`DbPool::begin_tenant`] or [`DbPool::begin_cross_tenant`],
/// pass `scope.conn()` to the store functions, then [`ScopedTx::commit`].
/// Dropping without committing rolls back, which is the right default for an
/// error path.
pub struct ScopedTx<'p> {
    tx: Transaction<'p, Postgres>,
}

impl<'p> ScopedTx<'p> {
    /// The connection to hand to store functions.
    pub fn conn(&mut self) -> &mut PgConnection {
        &mut self.tx
    }

    /// Commit the transaction, releasing the scope.
    pub async fn commit(self) -> Result<(), VaultError> {
        self.tx.commit().await.map_err(|e| VaultError::Database {
            reason: format!("commit failed: {e}"),
        })
    }

    /// Roll back explicitly. Dropping does the same thing; this is for the
    /// cases where saying so reads better than relying on the drop.
    pub async fn rollback(self) -> Result<(), VaultError> {
        self.tx.rollback().await.map_err(|e| VaultError::Database {
            reason: format!("rollback failed: {e}"),
        })
    }
}

impl std::fmt::Debug for ScopedTx<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScopedTx").finish_non_exhaustive()
    }
}

impl<'p> ScopedTx<'p> {
    /// Open a transaction scoped to `tenant` on a raw sqlx pool.
    ///
    /// Every RLS policy on a tenant table resolves against this value, so
    /// queries run inside the returned scope see that tenant's rows and no
    /// others — enforced by PostgreSQL, not by the query text.
    pub async fn tenant(pool: &'p PgPool, tenant: &TenantId) -> Result<Self, VaultError> {
        let mut tx = pool.begin().await.map_err(|e| VaultError::Database {
            reason: format!("begin failed: {e}"),
        })?;

        // `SET LOCAL` takes no bind parameters, so a naive implementation would
        // have to interpolate the tenant id into the statement text.
        // `set_config(name, value, is_local)` is the parameterised equivalent:
        // the id travels as a bound value and cannot alter the statement.
        sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
            .bind(tenant.0.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| VaultError::Database {
                reason: format!("failed to set tenant scope: {e}"),
            })?;

        Ok(Self { tx })
    }

    /// Open a transaction that deliberately spans every tenant, on a raw pool.
    ///
    /// For the jobs that are genuinely cross-tenant: the replication applier,
    /// the rotation sweep, root-key work. `reason` is required and logged, so a
    /// bypass leaves a trace and has to be justified at the call site rather
    /// than being a quiet default.
    pub async fn cross_tenant(pool: &'p PgPool, reason: &str) -> Result<Self, VaultError> {
        let mut tx = pool.begin().await.map_err(|e| VaultError::Database {
            reason: format!("begin failed: {e}"),
        })?;

        sqlx::query("SELECT set_config('app.bypass_rls', 'true', true)")
            .execute(&mut *tx)
            .await
            .map_err(|e| VaultError::Database {
                reason: format!("failed to set cross-tenant scope: {e}"),
            })?;

        tracing::debug!(reason, "opened cross-tenant transaction (RLS bypassed)");

        Ok(Self { tx })
    }
}

impl DbPool {
    /// Open a transaction scoped to `tenant`. See [`ScopedTx::tenant`].
    pub async fn begin_tenant(&self, tenant: &TenantId) -> Result<ScopedTx<'_>, VaultError> {
        ScopedTx::tenant(self.inner(), tenant).await
    }

    /// Open a transaction spanning every tenant. See [`ScopedTx::cross_tenant`].
    pub async fn begin_cross_tenant(&self, reason: &str) -> Result<ScopedTx<'_>, VaultError> {
        ScopedTx::cross_tenant(self.inner(), reason).await
    }
}
