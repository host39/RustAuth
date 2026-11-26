//! `AdminService`: account administration. Every operation requires an administrator.

use chrono::{DateTime, Utc};

use crate::entities::{Lockout, NewPassword, NewUser, Principal, User};
use crate::error::{AuthError, AuthResult};
use crate::ports::Ports;
use crate::services::inputs::{NewAccount, UserChanges};
use crate::values::{Page, Role, UserId};

pub struct AdminService {
    ports: Ports,
}

impl AdminService {
    pub fn new(ports: Ports) -> Self {
        Self { ports }
    }

    /// A page of accounts ordered by username, plus the total count.
    pub async fn list(&self, actor: &Principal, page: Page) -> AuthResult<(Vec<User>, u64)> {
        actor.require(Role::Administrator)?;
        self.ports.users.list(page).await
    }

    pub async fn get(&self, actor: &Principal, id: UserId) -> AuthResult<User> {
        actor.require(Role::Administrator)?;
        self.fetch(id).await
    }

    /// Creates an account with a temporary password and any role.
    pub async fn create(&self, actor: &Principal, account: NewAccount) -> AuthResult<User> {
        actor.require(Role::Administrator)?;
        let now = self.ports.clock.now();
        let hash = self.ports.hasher.hash(&account.password).await?;
        let user = self
            .ports
            .users
            .create(
                NewUser {
                    id: UserId::generate(),
                    username: account.username,
                    display_name: account.display_name,
                    role: account.role,
                    created_at: now,
                },
                NewPassword {
                    hash,
                    changed_at: now,
                },
            )
            .await?;
        tracing::info!(
            actor_id = %actor.user_id,
            user_id = %user.id,
            role = %user.role,
            "rustauth.admin.user-created"
        );
        Ok(user)
    }

    /// Changes display name, role, disabled state, or password. Any change revokes every session
    /// of that user (the actor's own included, when they change themselves), and a password reset
    /// also unlocks the account. Refuses to demote or disable the last enabled administrator
    /// (`LastAdministrator`). Without changes, returns the user untouched.
    pub async fn update(
        &self,
        actor: &Principal,
        id: UserId,
        changes: UserChanges,
    ) -> AuthResult<User> {
        actor.require(Role::Administrator)?;
        if changes.is_empty() {
            return self.fetch(id).await;
        }
        let UserChanges { patch, password } = changes;
        let now = self.ports.clock.now();
        let hash = match &password {
            Some(password) => Some(self.ports.hasher.hash(password).await?),
            None => None,
        };
        let mut user = if patch.is_empty() {
            self.fetch(id).await?
        } else {
            self.ports.users.update(id, &patch, now).await?
        };
        if let Some(hash) = hash {
            self.reset_password(actor, &mut user, hash, now).await?;
        }
        let revoked = self.ports.sessions.delete_all(id, None).await?;
        tracing::info!(
            actor_id = %actor.user_id,
            user_id = %id,
            revoked,
            "rustauth.admin.user-updated"
        );
        Ok(user)
    }

    /// Stores the new password hash and unlocks the account.
    async fn reset_password(
        &self,
        actor: &Principal,
        user: &mut User,
        hash: String,
        at: DateTime<Utc>,
    ) -> AuthResult<()> {
        self.ports.users.set_password(user.id, hash, at).await?;
        self.ports.users.unlock(user.id).await?;
        if !user.lockout.is_clear() {
            tracing::info!(user_id = %user.id, by = %actor.user_id, "rustauth.login.unlocked");
        }
        user.lockout = Lockout::default();
        tracing::info!(user_id = %user.id, by = %actor.user_id, "rustauth.admin.password-reset");
        Ok(())
    }

    /// Clears the account's lockout so the user can sign in again at once.
    pub async fn unlock(&self, actor: &Principal, id: UserId) -> AuthResult<()> {
        actor.require(Role::Administrator)?;
        self.fetch(id).await?;
        self.ports.users.unlock(id).await?;
        tracing::info!(user_id = %id, by = %actor.user_id, "rustauth.login.unlocked");
        Ok(())
    }

    /// Deletes the account with its credential and sessions. Refuses to delete the last enabled
    /// administrator (`LastAdministrator`).
    pub async fn delete(&self, actor: &Principal, id: UserId) -> AuthResult<()> {
        actor.require(Role::Administrator)?;
        if !self.ports.users.delete(id).await? {
            return Err(AuthError::not_found("User"));
        }
        tracing::info!(actor_id = %actor.user_id, user_id = %id, "rustauth.admin.user-deleted");
        Ok(())
    }

    async fn fetch(&self, id: UserId) -> AuthResult<User> {
        self.ports
            .users
            .get(id)
            .await?
            .ok_or(AuthError::not_found("User"))
    }
}

#[cfg(test)]
mod tests;
