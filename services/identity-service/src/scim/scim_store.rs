//! Abstraction layer for SCIM resource persistence.
//!
//! Defines the [`ScimStore`] trait with two implementations:
//! - [`MemoryScimStore`]: in-memory `HashMap` (default, for tests and when
//!   `DATABASE_URL` is not set).
//! - [`PgScimStore`]: PostgreSQL-backed via `sqlx` (production).
//!
//! All methods are async so the handlers can be uniform regardless of backend.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use chrono::Utc;
use sqlx::PgPool;

use super::schemas::{
    ScimEmail, ScimGroup, ScimGroupRef, ScimMemberRef, ScimMeta, ScimName, ScimUser, SCHEMA_GROUP,
    SCHEMA_USER,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur in SCIM store operations.
#[derive(Debug, thiserror::Error)]
pub enum ScimStoreError {
    #[error("store lock poisoned")]
    LockPoisoned,

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("serialization error: {0}")]
    Serialization(String),
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Async trait abstracting SCIM User and Group CRUD operations.
///
/// Handlers call these methods instead of accessing `HashMap` directly,
/// allowing transparent swapping between in-memory and database backends.
#[async_trait]
pub trait ScimStore: Send + Sync {
    // -- Users ---------------------------------------------------------------

    /// Returns the user with the given server-assigned ID, or `None`.
    async fn get_user(&self, id: &str) -> Result<Option<ScimUser>, ScimStoreError>;

    /// Returns `true` if a user with the given `userName` already exists
    /// (case-insensitive comparison).
    async fn user_exists_by_username(&self, user_name: &str) -> Result<bool, ScimStoreError>;

    /// Inserts a fully-populated `ScimUser` into the store.
    async fn insert_user(&self, user: &ScimUser) -> Result<(), ScimStoreError>;

    /// Replaces the user record with the same `id`.
    async fn update_user(&self, user: &ScimUser) -> Result<(), ScimStoreError>;

    /// Removes a user by ID. Returns `true` if a record was deleted.
    async fn delete_user(&self, id: &str) -> Result<bool, ScimStoreError>;

    /// Lists users with optional `userName` filter and pagination.
    /// Returns `(page, total_count)`.
    async fn list_users(
        &self,
        filter_username: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<ScimUser>, usize), ScimStoreError>;

    // -- Groups --------------------------------------------------------------

    /// Returns the group with the given server-assigned ID, or `None`.
    async fn get_group(&self, id: &str) -> Result<Option<ScimGroup>, ScimStoreError>;

    /// Returns `true` if a group with the given `displayName` already exists
    /// (case-insensitive comparison).
    async fn group_exists_by_display_name(
        &self,
        display_name: &str,
    ) -> Result<bool, ScimStoreError>;

    /// Inserts a fully-populated `ScimGroup` (with members) into the store.
    async fn insert_group(&self, group: &ScimGroup) -> Result<(), ScimStoreError>;

    /// Replaces the group record and its member list.
    async fn update_group(&self, group: &ScimGroup) -> Result<(), ScimStoreError>;

    /// Removes a group by ID. Returns the deleted group if it existed.
    async fn delete_group(&self, id: &str) -> Result<Option<ScimGroup>, ScimStoreError>;

    /// Lists groups with optional `displayName` filter and pagination.
    /// Returns `(page, total_count)`.
    async fn list_groups(
        &self,
        filter_display_name: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<ScimGroup>, usize), ScimStoreError>;
}

// ===========================================================================
// In-memory implementation
// ===========================================================================

/// In-memory SCIM store backed by `HashMap` behind `RwLock`.
///
/// Used for tests and when `DATABASE_URL` is not configured.
pub struct MemoryScimStore {
    users: Arc<RwLock<HashMap<String, ScimUser>>>,
    groups: Arc<RwLock<HashMap<String, ScimGroup>>>,
}

impl MemoryScimStore {
    pub fn new() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            groups: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl ScimStore for MemoryScimStore {
    // -- Users ---------------------------------------------------------------

    async fn get_user(&self, id: &str) -> Result<Option<ScimUser>, ScimStoreError> {
        let users = self
            .users
            .read()
            .map_err(|_| ScimStoreError::LockPoisoned)?;
        Ok(users.get(id).cloned())
    }

    async fn user_exists_by_username(&self, user_name: &str) -> Result<bool, ScimStoreError> {
        let users = self
            .users
            .read()
            .map_err(|_| ScimStoreError::LockPoisoned)?;
        Ok(users
            .values()
            .any(|u| u.user_name.eq_ignore_ascii_case(user_name)))
    }

    async fn insert_user(&self, user: &ScimUser) -> Result<(), ScimStoreError> {
        let mut users = self
            .users
            .write()
            .map_err(|_| ScimStoreError::LockPoisoned)?;
        if let Some(id) = &user.id {
            users.insert(id.clone(), user.clone());
        }
        Ok(())
    }

    async fn update_user(&self, user: &ScimUser) -> Result<(), ScimStoreError> {
        let mut users = self
            .users
            .write()
            .map_err(|_| ScimStoreError::LockPoisoned)?;
        if let Some(id) = &user.id {
            users.insert(id.clone(), user.clone());
        }
        Ok(())
    }

    async fn delete_user(&self, id: &str) -> Result<bool, ScimStoreError> {
        let mut users = self
            .users
            .write()
            .map_err(|_| ScimStoreError::LockPoisoned)?;
        Ok(users.remove(id).is_some())
    }

    async fn list_users(
        &self,
        filter_username: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<ScimUser>, usize), ScimStoreError> {
        let users = self
            .users
            .read()
            .map_err(|_| ScimStoreError::LockPoisoned)?;
        let mut matched: Vec<ScimUser> = users.values().cloned().collect();

        if let Some(target) = filter_username {
            matched.retain(|u| u.user_name.eq_ignore_ascii_case(target));
        }

        let total = matched.len();
        let page: Vec<ScimUser> = matched.into_iter().skip(offset).take(limit).collect();
        Ok((page, total))
    }

    // -- Groups --------------------------------------------------------------

    async fn get_group(&self, id: &str) -> Result<Option<ScimGroup>, ScimStoreError> {
        let groups = self
            .groups
            .read()
            .map_err(|_| ScimStoreError::LockPoisoned)?;
        Ok(groups.get(id).cloned())
    }

    async fn group_exists_by_display_name(
        &self,
        display_name: &str,
    ) -> Result<bool, ScimStoreError> {
        let groups = self
            .groups
            .read()
            .map_err(|_| ScimStoreError::LockPoisoned)?;
        Ok(groups
            .values()
            .any(|g| g.display_name.eq_ignore_ascii_case(display_name)))
    }

    async fn insert_group(&self, group: &ScimGroup) -> Result<(), ScimStoreError> {
        let mut groups = self
            .groups
            .write()
            .map_err(|_| ScimStoreError::LockPoisoned)?;
        if let Some(id) = &group.id {
            groups.insert(id.clone(), group.clone());
        }
        Ok(())
    }

    async fn update_group(&self, group: &ScimGroup) -> Result<(), ScimStoreError> {
        let mut groups = self
            .groups
            .write()
            .map_err(|_| ScimStoreError::LockPoisoned)?;
        if let Some(id) = &group.id {
            groups.insert(id.clone(), group.clone());
        }
        Ok(())
    }

    async fn delete_group(&self, id: &str) -> Result<Option<ScimGroup>, ScimStoreError> {
        let mut groups = self
            .groups
            .write()
            .map_err(|_| ScimStoreError::LockPoisoned)?;
        Ok(groups.remove(id))
    }

    async fn list_groups(
        &self,
        filter_display_name: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<ScimGroup>, usize), ScimStoreError> {
        let groups = self
            .groups
            .read()
            .map_err(|_| ScimStoreError::LockPoisoned)?;
        let mut matched: Vec<ScimGroup> = groups.values().cloned().collect();

        if let Some(target) = filter_display_name {
            matched.retain(|g| g.display_name.eq_ignore_ascii_case(target));
        }

        let total = matched.len();
        let page: Vec<ScimGroup> = matched.into_iter().skip(offset).take(limit).collect();
        Ok((page, total))
    }
}

// ===========================================================================
// PostgreSQL implementation
// ===========================================================================

/// PostgreSQL-backed SCIM store using `sqlx::PgPool`.
pub struct PgScimStore {
    pool: PgPool,
}

impl PgScimStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Reconstructs a `ScimUser` from a database row.
    fn row_to_user(row: &PgUserRow) -> ScimUser {
        let emails: Vec<ScimEmail> = serde_json::from_value(row.emails.clone()).unwrap_or_default();
        let groups: Vec<ScimGroupRef> =
            serde_json::from_value(row.groups_ref.clone()).unwrap_or_default();

        let name = if row.name_given.is_some()
            || row.name_family.is_some()
            || row.name_formatted.is_some()
        {
            Some(ScimName {
                formatted: row.name_formatted.clone(),
                family_name: row.name_family.clone(),
                given_name: row.name_given.clone(),
            })
        } else {
            None
        };

        ScimUser {
            schemas: vec![SCHEMA_USER.to_string()],
            id: Some(row.id.clone()),
            external_id: row.external_id.clone(),
            user_name: row.user_name.clone(),
            name,
            emails,
            display_name: row.display_name.clone(),
            active: Some(row.active),
            groups,
            meta: Some(ScimMeta {
                resource_type: "User".to_string(),
                created: row.created_at.to_rfc3339(),
                last_modified: row.updated_at.to_rfc3339(),
                location: format!("/scim/v2/Users/{}", row.id),
                version: None,
            }),
        }
    }

    /// Reconstructs a `ScimGroup` from a database row plus its members.
    fn row_to_group(row: &PgGroupRow, members: Vec<ScimMemberRef>) -> ScimGroup {
        ScimGroup {
            schemas: vec![SCHEMA_GROUP.to_string()],
            id: Some(row.id.clone()),
            display_name: row.display_name.clone(),
            members,
            meta: Some(ScimMeta {
                resource_type: "Group".to_string(),
                created: row.created_at.to_rfc3339(),
                last_modified: row.updated_at.to_rfc3339(),
                location: format!("/scim/v2/Groups/{}", row.id),
                version: None,
            }),
        }
    }

    /// Fetches group members from the join table.
    async fn fetch_members(&self, group_id: &str) -> Result<Vec<ScimMemberRef>, sqlx::Error> {
        let rows = sqlx::query_as::<_, PgMemberRow>(
            "SELECT user_id, display, member_type FROM shared.scim_group_members WHERE group_id = $1",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| ScimMemberRef {
                value: r.user_id,
                display: r.display,
                member_type: Some(r.member_type),
            })
            .collect())
    }

    /// Replaces all members for a group in a single transaction step.
    async fn sync_members(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        group_id: &str,
        members: &[ScimMemberRef],
    ) -> Result<(), sqlx::Error> {
        // Delete existing memberships.
        sqlx::query("DELETE FROM shared.scim_group_members WHERE group_id = $1")
            .bind(group_id)
            .execute(&mut **tx)
            .await?;

        // Insert new memberships.
        for member in members {
            sqlx::query(
                "INSERT INTO shared.scim_group_members (group_id, user_id, display, member_type) \
                 VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (group_id, user_id) DO NOTHING",
            )
            .bind(group_id)
            .bind(&member.value)
            .bind(&member.display)
            .bind(member.member_type.as_deref().unwrap_or("User"))
            .execute(&mut **tx)
            .await?;
        }

        Ok(())
    }
}

// Internal row types for sqlx mapping.

#[derive(sqlx::FromRow)]
struct PgUserRow {
    id: String,
    external_id: Option<String>,
    #[allow(dead_code)]
    tenant_id: String,
    user_name: String,
    display_name: Option<String>,
    active: bool,
    name_formatted: Option<String>,
    name_given: Option<String>,
    name_family: Option<String>,
    emails: serde_json::Value,
    groups_ref: serde_json::Value,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct PgGroupRow {
    id: String,
    #[allow(dead_code)]
    tenant_id: String,
    display_name: String,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct PgMemberRow {
    user_id: String,
    display: Option<String>,
    member_type: String,
}

#[derive(sqlx::FromRow)]
struct CountRow {
    count: i64,
}

#[async_trait]
impl ScimStore for PgScimStore {
    // -- Users ---------------------------------------------------------------

    async fn get_user(&self, id: &str) -> Result<Option<ScimUser>, ScimStoreError> {
        let row = sqlx::query_as::<_, PgUserRow>("SELECT * FROM shared.scim_users WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(row.as_ref().map(Self::row_to_user))
    }

    async fn user_exists_by_username(&self, user_name: &str) -> Result<bool, ScimStoreError> {
        let row = sqlx::query_as::<_, CountRow>(
            "SELECT COUNT(*) AS count FROM shared.scim_users WHERE lower(user_name) = lower($1)",
        )
        .bind(user_name)
        .fetch_one(&self.pool)
        .await?;

        Ok(row.count > 0)
    }

    async fn insert_user(&self, user: &ScimUser) -> Result<(), ScimStoreError> {
        let id = user.id.as_deref().unwrap_or_default();
        let emails_json = serde_json::to_value(&user.emails)
            .map_err(|e| ScimStoreError::Serialization(e.to_string()))?;
        let groups_json = serde_json::to_value(&user.groups)
            .map_err(|e| ScimStoreError::Serialization(e.to_string()))?;

        sqlx::query(
            "INSERT INTO shared.scim_users \
             (id, external_id, user_name, display_name, active, \
              name_formatted, name_given, name_family, emails, groups_ref) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(id)
        .bind(&user.external_id)
        .bind(&user.user_name)
        .bind(&user.display_name)
        .bind(user.active.unwrap_or(true))
        .bind(user.name.as_ref().and_then(|n| n.formatted.as_deref()))
        .bind(user.name.as_ref().and_then(|n| n.given_name.as_deref()))
        .bind(user.name.as_ref().and_then(|n| n.family_name.as_deref()))
        .bind(&emails_json)
        .bind(&groups_json)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn update_user(&self, user: &ScimUser) -> Result<(), ScimStoreError> {
        let id = user.id.as_deref().unwrap_or_default();
        let emails_json = serde_json::to_value(&user.emails)
            .map_err(|e| ScimStoreError::Serialization(e.to_string()))?;
        let groups_json = serde_json::to_value(&user.groups)
            .map_err(|e| ScimStoreError::Serialization(e.to_string()))?;

        sqlx::query(
            "UPDATE shared.scim_users SET \
             external_id = $2, user_name = $3, display_name = $4, active = $5, \
             name_formatted = $6, name_given = $7, name_family = $8, \
             emails = $9, groups_ref = $10 \
             WHERE id = $1",
        )
        .bind(id)
        .bind(&user.external_id)
        .bind(&user.user_name)
        .bind(&user.display_name)
        .bind(user.active.unwrap_or(true))
        .bind(user.name.as_ref().and_then(|n| n.formatted.as_deref()))
        .bind(user.name.as_ref().and_then(|n| n.given_name.as_deref()))
        .bind(user.name.as_ref().and_then(|n| n.family_name.as_deref()))
        .bind(&emails_json)
        .bind(&groups_json)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete_user(&self, id: &str) -> Result<bool, ScimStoreError> {
        let result = sqlx::query("DELETE FROM shared.scim_users WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn list_users(
        &self,
        filter_username: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<ScimUser>, usize), ScimStoreError> {
        let (count_row, rows) = match filter_username {
            Some(target) => {
                let count = sqlx::query_as::<_, CountRow>(
                    "SELECT COUNT(*) AS count FROM shared.scim_users \
                     WHERE lower(user_name) = lower($1)",
                )
                .bind(target)
                .fetch_one(&self.pool)
                .await?;

                let rows = sqlx::query_as::<_, PgUserRow>(
                    "SELECT * FROM shared.scim_users \
                     WHERE lower(user_name) = lower($1) \
                     ORDER BY created_at \
                     OFFSET $2 LIMIT $3",
                )
                .bind(target)
                .bind(offset as i64)
                .bind(limit as i64)
                .fetch_all(&self.pool)
                .await?;

                (count, rows)
            }
            None => {
                let count = sqlx::query_as::<_, CountRow>(
                    "SELECT COUNT(*) AS count FROM shared.scim_users",
                )
                .fetch_one(&self.pool)
                .await?;

                let rows = sqlx::query_as::<_, PgUserRow>(
                    "SELECT * FROM shared.scim_users \
                     ORDER BY created_at \
                     OFFSET $1 LIMIT $2",
                )
                .bind(offset as i64)
                .bind(limit as i64)
                .fetch_all(&self.pool)
                .await?;

                (count, rows)
            }
        };

        let users: Vec<ScimUser> = rows.iter().map(Self::row_to_user).collect();
        Ok((users, count_row.count as usize))
    }

    // -- Groups --------------------------------------------------------------

    async fn get_group(&self, id: &str) -> Result<Option<ScimGroup>, ScimStoreError> {
        let row = sqlx::query_as::<_, PgGroupRow>("SELECT * FROM shared.scim_groups WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(r) => {
                let members = self.fetch_members(id).await?;
                Ok(Some(Self::row_to_group(&r, members)))
            }
            None => Ok(None),
        }
    }

    async fn group_exists_by_display_name(
        &self,
        display_name: &str,
    ) -> Result<bool, ScimStoreError> {
        let row = sqlx::query_as::<_, CountRow>(
            "SELECT COUNT(*) AS count FROM shared.scim_groups \
             WHERE lower(display_name) = lower($1)",
        )
        .bind(display_name)
        .fetch_one(&self.pool)
        .await?;

        Ok(row.count > 0)
    }

    async fn insert_group(&self, group: &ScimGroup) -> Result<(), ScimStoreError> {
        let id = group.id.as_deref().unwrap_or_default();

        let mut tx = self.pool.begin().await?;

        sqlx::query("INSERT INTO shared.scim_groups (id, display_name) VALUES ($1, $2)")
            .bind(id)
            .bind(&group.display_name)
            .execute(&mut *tx)
            .await?;

        self.sync_members(&mut tx, id, &group.members).await?;

        tx.commit().await?;
        Ok(())
    }

    async fn update_group(&self, group: &ScimGroup) -> Result<(), ScimStoreError> {
        let id = group.id.as_deref().unwrap_or_default();

        let mut tx = self.pool.begin().await?;

        sqlx::query("UPDATE shared.scim_groups SET display_name = $2 WHERE id = $1")
            .bind(id)
            .bind(&group.display_name)
            .execute(&mut *tx)
            .await?;

        self.sync_members(&mut tx, id, &group.members).await?;

        tx.commit().await?;
        Ok(())
    }

    async fn delete_group(&self, id: &str) -> Result<Option<ScimGroup>, ScimStoreError> {
        // Fetch before deleting so we can return the group for policy cleanup.
        let existing = self.get_group(id).await?;

        if existing.is_some() {
            // Memberships are cascade-deleted via FK.
            sqlx::query("DELETE FROM shared.scim_groups WHERE id = $1")
                .bind(id)
                .execute(&self.pool)
                .await?;
        }

        Ok(existing)
    }

    async fn list_groups(
        &self,
        filter_display_name: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<ScimGroup>, usize), ScimStoreError> {
        let (count_row, rows) = match filter_display_name {
            Some(target) => {
                let count = sqlx::query_as::<_, CountRow>(
                    "SELECT COUNT(*) AS count FROM shared.scim_groups \
                     WHERE lower(display_name) = lower($1)",
                )
                .bind(target)
                .fetch_one(&self.pool)
                .await?;

                let rows = sqlx::query_as::<_, PgGroupRow>(
                    "SELECT * FROM shared.scim_groups \
                     WHERE lower(display_name) = lower($1) \
                     ORDER BY created_at \
                     OFFSET $2 LIMIT $3",
                )
                .bind(target)
                .bind(offset as i64)
                .bind(limit as i64)
                .fetch_all(&self.pool)
                .await?;

                (count, rows)
            }
            None => {
                let count = sqlx::query_as::<_, CountRow>(
                    "SELECT COUNT(*) AS count FROM shared.scim_groups",
                )
                .fetch_one(&self.pool)
                .await?;

                let rows = sqlx::query_as::<_, PgGroupRow>(
                    "SELECT * FROM shared.scim_groups \
                     ORDER BY created_at \
                     OFFSET $1 LIMIT $2",
                )
                .bind(offset as i64)
                .bind(limit as i64)
                .fetch_all(&self.pool)
                .await?;

                (count, rows)
            }
        };

        let mut groups: Vec<ScimGroup> = Vec::with_capacity(rows.len());
        for row in &rows {
            let members = self.fetch_members(&row.id).await?;
            groups.push(Self::row_to_group(row, members));
        }

        Ok((groups, count_row.count as usize))
    }
}
