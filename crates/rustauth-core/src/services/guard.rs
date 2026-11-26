//! `LoginGuard`: brute-force protection for password checks.
//!
//! Three layers (see "Brute-Force Protection" in the design):
//!
//! 1. Account lockout, persisted through `UserRepository::record_failure` and `lock`. The lock
//!    is checked before the password, so even the correct password fails and no hashing work is
//!    spent while it lasts. Each consecutive lockout doubles the duration, up to the maximum.
//! 2. Unknown usernames count the same way in memory, so lockout does not reveal which accounts
//!    exist.
//! 3. Failed sign-ins per client IP, counted in memory per failure window.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, TimeDelta, Utc};

use crate::config::AuthConfig;
use crate::entities::{Lockout, User};
use crate::error::{AuthError, AuthResult};
use crate::ports::{Clock, UserRepository};
use crate::services::shared::{MAX_ENTRIES, ip_key, lock, seconds_until};
use crate::values::ClientInfo;

/// Longest unknown username kept as a key; longer input is cut, which only merges junk keys.
const MAX_KEY_CHARS: usize = 64;

/// Who a sign-in attempt is for.
#[derive(Clone, Copy, Debug)]
pub enum Attempt<'a> {
    /// An existing account; its lockout state is persisted.
    Known(&'a User),
    /// A username with no account (as typed); its state is kept in memory.
    Unknown(&'a str),
}

/// Failed sign-ins of one client IP in the current window.
#[derive(Clone, Copy, Debug)]
struct Failures {
    start: DateTime<Utc>,
    count: u32,
}

pub struct LoginGuard {
    users: Arc<dyn UserRepository>,
    clock: Arc<dyn Clock>,
    threshold: u32,
    duration: TimeDelta,
    max: TimeDelta,
    window: TimeDelta,
    ip_limit: u32,
    unknown: Mutex<HashMap<String, Lockout>>,
    ips: Mutex<HashMap<IpAddr, Failures>>,
}

impl LoginGuard {
    pub fn new(users: Arc<dyn UserRepository>, clock: Arc<dyn Clock>, config: &AuthConfig) -> Self {
        Self {
            users,
            clock,
            threshold: config.lockout_threshold(),
            duration: config.lockout_duration(),
            max: config.lockout_max(),
            window: config.failure_window(),
            ip_limit: config.ip_failure_limit(),
            unknown: Mutex::new(HashMap::new()),
            ips: Mutex::new(HashMap::new()),
        }
    }

    /// Refuses a client that is over the per-IP failure limit (`RateLimited`). Clients without a
    /// known IP are not limited here.
    pub fn admit(&self, client: &ClientInfo) -> AuthResult<()> {
        let Some(ip) = client.ip() else {
            return Ok(());
        };
        let now = self.clock.now();
        let ips = lock(&self.ips);
        if let Some(failures) = ips.get(&ip_key(ip)) {
            let end = failures.start + self.window;
            if now < end && failures.count >= self.ip_limit {
                return Err(AuthError::RateLimited {
                    retry_after_secs: seconds_until(now, end),
                });
            }
        }
        Ok(())
    }

    /// Refuses an attempt on a locked account (`AccountLocked`). Call it before checking the
    /// password.
    pub fn check(&self, attempt: &Attempt<'_>) -> AuthResult<()> {
        let now = self.clock.now();
        let until = match attempt {
            Attempt::Known(user) => user.lockout.locked(now),
            Attempt::Unknown(username) => lock(&self.unknown)
                .get(&key(username))
                .and_then(|lockout| lockout.locked(now)),
        };
        match until {
            Some(until) => Err(AuthError::AccountLocked {
                retry_after_secs: seconds_until(now, until),
            }),
            None => Ok(()),
        }
    }

    /// Records a wrong password and returns the error for the caller to return:
    /// `InvalidCredentials`, or `AccountLocked` when this failure reached the threshold.
    pub async fn fail(&self, client: &ClientInfo, attempt: &Attempt<'_>) -> AuthError {
        let now = self.clock.now();
        let since = now - self.window;
        self.record_ip(client, now);
        match attempt {
            Attempt::Known(user) => self
                .fail_known(user, client, now, since)
                .await
                .unwrap_or_else(|error| error),
            Attempt::Unknown(username) => self.fail_unknown(username, client, now, since),
        }
    }

    /// Clears the account's failure state after a correct password.
    pub async fn succeed(&self, user: &User) -> AuthResult<()> {
        if user.lockout.is_clear() {
            return Ok(());
        }
        self.users.unlock(user.id).await
    }

    /// Length of the lockout that follows `lockouts` earlier consecutive ones: the first
    /// duration, doubled each time, capped at the maximum.
    pub fn duration(&self, lockouts: u32) -> TimeDelta {
        let factor = 1i32 << lockouts.min(30);
        self.duration
            .checked_mul(factor)
            .map_or(self.max, |duration| duration.min(self.max))
    }

    async fn fail_known(
        &self,
        user: &User,
        client: &ClientInfo,
        now: DateTime<Utc>,
        since: DateTime<Utc>,
    ) -> AuthResult<AuthError> {
        let lockout = match self.users.record_failure(user.id, now, since).await {
            Ok(lockout) => lockout,
            // Deleted since it was loaded: answer as for any unknown account.
            Err(AuthError::NotFound { .. }) => return Ok(AuthError::InvalidCredentials),
            Err(error) => return Err(error),
        };
        tracing::warn!(
            user_id = %user.id,
            ip = ?client.ip(),
            count = lockout.failed_count,
            "rustauth.login.failed"
        );
        if lockout.failed_count < self.threshold {
            return Ok(AuthError::InvalidCredentials);
        }
        let until = now + self.duration(lockout.lockouts);
        // `false` means a concurrent failure locked the account first; it is locked either way.
        if self.users.lock(user.id, until, lockout.lockouts).await? {
            tracing::info!(user_id = %user.id, until = %until, "rustauth.login.locked");
        }
        Ok(AuthError::AccountLocked {
            retry_after_secs: seconds_until(now, until),
        })
    }

    fn fail_unknown(
        &self,
        username: &str,
        client: &ClientInfo,
        now: DateTime<Utc>,
        since: DateTime<Utc>,
    ) -> AuthError {
        let key = key(username);
        let mut unknown = lock(&self.unknown);
        if !unknown.contains_key(&key) && unknown.len() >= MAX_ENTRIES {
            prune_unknown(&mut unknown, now, since);
        }
        let entry = unknown.entry(key).or_default();
        *entry = entry.fail(now, since);
        tracing::warn!(
            user_id = "unknown",
            ip = ?client.ip(),
            count = entry.failed_count,
            "rustauth.login.failed"
        );
        if entry.failed_count < self.threshold {
            return AuthError::InvalidCredentials;
        }
        let until = now + self.duration(entry.lockouts);
        *entry = entry.lock(until);
        tracing::info!(user_id = "unknown", until = %until, "rustauth.login.locked");
        AuthError::AccountLocked {
            retry_after_secs: seconds_until(now, until),
        }
    }

    fn record_ip(&self, client: &ClientInfo, now: DateTime<Utc>) {
        let Some(ip) = client.ip() else {
            return;
        };
        let key = ip_key(ip);
        let mut ips = lock(&self.ips);
        if !ips.contains_key(&key) && ips.len() >= MAX_ENTRIES {
            let window = self.window;
            ips.retain(|_, failures| now < failures.start + window);
            if ips.len() >= MAX_ENTRIES
                && let Some(oldest) = ips
                    .iter()
                    .min_by_key(|(_, failures)| failures.start)
                    .map(|(ip, _)| *ip)
            {
                ips.remove(&oldest);
            }
        }
        let failures = ips.entry(key).or_insert(Failures {
            start: now,
            count: 0,
        });
        if now >= failures.start + self.window {
            *failures = Failures {
                start: now,
                count: 0,
            };
        }
        failures.count = failures.count.saturating_add(1);
    }
}

/// The in-memory key for an unknown username: trimmed, lowercase, and bounded in length.
fn key(username: &str) -> String {
    username
        .trim()
        .to_lowercase()
        .chars()
        .take(MAX_KEY_CHARS)
        .collect()
}

/// Drops unknown usernames that are neither locked nor inside the failure window; if the map is
/// still full, drops the one with the oldest failure.
fn prune_unknown(unknown: &mut HashMap<String, Lockout>, now: DateTime<Utc>, since: DateTime<Utc>) {
    unknown.retain(|_, lockout| {
        lockout.locked(now).is_some() || lockout.last_failed_at.is_some_and(|last| last >= since)
    });
    if unknown.len() >= MAX_ENTRIES
        && let Some(oldest) = unknown
            .iter()
            .min_by_key(|(_, lockout)| lockout.last_failed_at)
            .map(|(key, _)| key.clone())
    {
        unknown.remove(&oldest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fakes;
    use crate::values::{DisplayName, Role, UserId, Username};

    fn guard(config: &AuthConfig) -> (Fakes, LoginGuard) {
        let fakes = Fakes::new();
        let guard = LoginGuard::new(fakes.store.clone(), fakes.clock.clone(), config);
        (fakes, guard)
    }

    #[tokio::test]
    async fn a_deleted_account_fails_like_an_unknown_one() {
        let (fakes, guard) = guard(&AuthConfig::default());
        // Never stored, as if deleted after the sign-in loaded it.
        let user = User {
            id: UserId::generate(),
            username: Username::new("gone").expect("valid"),
            display_name: DisplayName::new("Gone").expect("valid"),
            role: Role::User,
            disabled_at: None,
            created_at: fakes.clock.now(),
            updated_at: fakes.clock.now(),
            lockout: Lockout::default(),
        };
        let error = guard
            .fail(&ClientInfo::default(), &Attempt::Known(&user))
            .await;
        assert!(matches!(error, AuthError::InvalidCredentials), "{error:?}");
    }

    #[test]
    fn doubles_the_lockout_up_to_the_maximum() {
        let (_, guard) = guard(&AuthConfig::default());
        assert_eq!(guard.duration(0), TimeDelta::minutes(15));
        assert_eq!(guard.duration(1), TimeDelta::minutes(30));
        assert_eq!(guard.duration(2), TimeDelta::minutes(60));
        assert_eq!(guard.duration(6), TimeDelta::minutes(960));
        assert_eq!(guard.duration(7), TimeDelta::hours(24));
        assert_eq!(guard.duration(u32::MAX), TimeDelta::hours(24));
    }

    #[tokio::test]
    async fn unknown_usernames_share_a_key_regardless_of_case() {
        let config = AuthConfig::builder()
            .lockout_threshold(2)
            .build()
            .expect("valid");
        let (_, guard) = guard(&config);
        let client = ClientInfo::default();
        let first = guard.fail(&client, &Attempt::Unknown("Ghost")).await;
        assert!(matches!(first, AuthError::InvalidCredentials));
        let second = guard.fail(&client, &Attempt::Unknown(" ghost ")).await;
        assert!(matches!(second, AuthError::AccountLocked { .. }));
        assert!(guard.check(&Attempt::Unknown("GHOST")).is_err());
        assert!(guard.check(&Attempt::Unknown("someone_else")).is_ok());
    }

    #[tokio::test]
    async fn bounds_the_unknown_username_map() {
        let (fakes, guard) = guard(&AuthConfig::default());
        let client = ClientInfo::default();
        for index in 0..MAX_ENTRIES {
            guard
                .fail(&client, &Attempt::Unknown(&format!("user{index}")))
                .await;
        }
        assert_eq!(lock(&guard.unknown).len(), MAX_ENTRIES);
        // Every entry is inside the window: the oldest one makes room.
        guard.fail(&client, &Attempt::Unknown("newcomer")).await;
        assert_eq!(lock(&guard.unknown).len(), MAX_ENTRIES);
        // Once the window has passed, the stale entries are dropped together.
        fakes.clock.advance(TimeDelta::minutes(16));
        guard.fail(&client, &Attempt::Unknown("latecomer")).await;
        assert_eq!(lock(&guard.unknown).len(), 1);
    }

    #[tokio::test]
    async fn bounds_the_ip_map() {
        let (fakes, guard) = guard(&AuthConfig::default());
        for index in 0..MAX_ENTRIES {
            let index = u32::try_from(index).expect("small");
            let client = ClientInfo::new(Some(IpAddr::V4(index.into())), "");
            guard.record_ip(&client, fakes.clock.now());
        }
        assert_eq!(lock(&guard.ips).len(), MAX_ENTRIES);
        fakes.clock.advance(TimeDelta::minutes(16));
        let client = ClientInfo::new(Some("198.51.100.1".parse().expect("valid")), "");
        guard.record_ip(&client, fakes.clock.now());
        assert_eq!(lock(&guard.ips).len(), 1);
    }
}
