//! `LoginGuard`: brute-force protection for password checks.
//!
//! Three layers (see "Brute-Force Protection" in the design):
//!
//! 1. Account lockout, persisted through the `UserRepository` lockout steps. Every password check
//!    is reserved before it runs ([`LoginGuard::begin`]): one atomic step counts it as a failure
//!    and refuses it while the account is locked or the failure window already holds the
//!    threshold, so concurrent attempts cannot get around the limit and no hashing work is spent
//!    on a refused one. A correct password then clears the count ([`LoginGuard::succeed`]) unless
//!    a concurrent failure locked the account meanwhile (the lock wins), and a wrong one that
//!    reached the threshold locks it ([`LoginGuard::fail`]). Each consecutive lockout doubles the
//!    duration, up to the maximum.
//! 2. Usernames without an account take the same steps in the same storage
//!    ([`Subject::Name`]), so lockout does not reveal which accounts exist, on any instance.
//! 3. Failed sign-ins per client IP, counted in memory per failure window. An attempt counts from
//!    the moment it is admitted ([`LoginGuard::admit`]), so concurrent attempts cannot get around
//!    this limit either; it is given back unless its password check failed.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, TimeDelta, Utc};

use crate::config::AuthConfig;
use crate::entities::{Lockout, Reservation, Subject};
use crate::error::{AuthError, AuthResult};
use crate::ports::{Clock, UserRepository};
use crate::services::shared::{MAX_ENTRIES, ip_key, lock, seconds_until};
use crate::values::ClientInfo;

/// Failed sign-ins of one client IP in the current window, running ones included.
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
    ips: Mutex<HashMap<IpAddr, Failures>>,
}

/// One sign-in attempt, counted against its client IP while it runs ([`LoginGuard::admit`]).
/// Dropping it gives the count back; [`Slot::keep`] keeps it as a failure.
#[must_use = "dropping the slot gives the attempt back at once"]
pub struct Slot<'a> {
    guard: &'a LoginGuard,
    /// The IP key and the start of the window the attempt counts in.
    counted: Option<(IpAddr, DateTime<Utc>)>,
}

impl Slot<'_> {
    /// Keeps the attempt as a failure of its client IP: its password check failed.
    pub fn keep(mut self) {
        self.counted = None;
    }
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        if let Some((key, start)) = self.counted.take() {
            self.guard.release(key, start);
        }
    }
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
            ips: Mutex::new(HashMap::new()),
        }
    }

    /// Counts an attempt against its client IP, or refuses it (`RateLimited`) when the window
    /// already holds the per-IP limit of failures, finished or running. Clients without a known
    /// IP are not limited here.
    pub fn admit(&self, client: &ClientInfo) -> AuthResult<Slot<'_>> {
        let Some(ip) = client.ip() else {
            return Ok(Slot {
                guard: self,
                counted: None,
            });
        };
        let now = self.clock.now();
        let key = ip_key(ip);
        let window = self.window;
        let mut ips = lock(&self.ips);
        if !ips.contains_key(&key) && ips.len() >= MAX_ENTRIES {
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
        if now >= failures.start + window {
            *failures = Failures {
                start: now,
                count: 0,
            };
        }
        if failures.count >= self.ip_limit {
            return Err(AuthError::RateLimited {
                retry_after_secs: seconds_until(now, failures.start + window),
            });
        }
        failures.count = failures.count.saturating_add(1);
        Ok(Slot {
            guard: self,
            counted: Some((key, failures.start)),
        })
    }

    /// Reserves a password check for `subject` (see [`Lockout::reserve`]) and returns the state
    /// with it counted, for [`LoginGuard::fail`]. Refuses with `AccountLocked` while the subject
    /// is locked or its window is full. Call it before checking the password.
    pub async fn begin(&self, subject: &Subject) -> AuthResult<Lockout> {
        let now = self.clock.now();
        match self
            .users
            .reserve(subject, now, now - self.window, self.threshold)
            .await?
        {
            Reservation::Granted(lockout) => Ok(lockout),
            // Full but not locked yet: a running check holds the last failure the window allows,
            // and the lock it may set is the wait.
            Reservation::Refused(lockout) => {
                let until = lockout
                    .locked(now)
                    .unwrap_or_else(|| now + self.duration(lockout.lockouts));
                Err(AuthError::AccountLocked {
                    retry_after_secs: seconds_until(now, until),
                })
            }
        }
    }

    /// Settles a wrong password whose check [`LoginGuard::begin`] reserved (`seen`), and returns
    /// the error for the caller to return: `InvalidCredentials`, or `AccountLocked` when this
    /// failure reached the threshold (it locks the subject then).
    pub async fn fail(&self, client: &ClientInfo, subject: &Subject, seen: Lockout) -> AuthError {
        self.settle(client, subject, seen)
            .await
            .unwrap_or_else(|error| error)
    }

    /// Clears the subject's failures after a correct password, or fails with `AccountLocked`
    /// when a concurrent failure locked it during the check.
    pub async fn succeed(&self, subject: &Subject) -> AuthResult<()> {
        let now = self.clock.now();
        match self.users.clear(subject, now).await? {
            None => Ok(()),
            Some(lockout) => Err(AuthError::AccountLocked {
                retry_after_secs: seconds_until(now, lockout.locked(now).unwrap_or(now)),
            }),
        }
    }

    /// Length of the lockout that follows `lockouts` earlier consecutive ones: the first
    /// duration, doubled each time, capped at the maximum.
    pub fn duration(&self, lockouts: u32) -> TimeDelta {
        let factor = 1i32 << lockouts.min(30);
        self.duration
            .checked_mul(factor)
            .map_or(self.max, |duration| duration.min(self.max))
    }

    async fn settle(
        &self,
        client: &ClientInfo,
        subject: &Subject,
        seen: Lockout,
    ) -> AuthResult<AuthError> {
        let user_id = match subject {
            Subject::User(id) => id.to_string(),
            Subject::Name(_) => "unknown".to_owned(),
        };
        tracing::warn!(
            user_id,
            ip = ?client.ip(),
            count = seen.failed_count,
            "rustauth.login.failed"
        );
        if seen.failed_count < self.threshold {
            return Ok(AuthError::InvalidCredentials);
        }
        let now = self.clock.now();
        let until = now + self.duration(seen.lockouts);
        // `false` means a concurrent failure locked first (it is locked either way) or a correct
        // password cleared the count meanwhile; this attempt used the last check either way.
        if self.users.lock(subject, seen, until).await? {
            tracing::info!(user_id, until = %until, "rustauth.login.locked");
        }
        Ok(AuthError::AccountLocked {
            retry_after_secs: seconds_until(now, until),
        })
    }

    /// Gives back an attempt counted in the window that started at `start`.
    fn release(&self, key: IpAddr, start: DateTime<Utc>) {
        let mut ips = lock(&self.ips);
        if let Some(failures) = ips.get_mut(&key)
            && failures.start == start
        {
            failures.count = failures.count.saturating_sub(1);
            if failures.count == 0 {
                ips.remove(&key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fakes;
    use crate::values::{UserId, Username};

    fn guard(config: &AuthConfig) -> (Fakes, LoginGuard) {
        let fakes = Fakes::new();
        let guard = LoginGuard::new(fakes.store.clone(), fakes.clock.clone(), config);
        (fakes, guard)
    }

    fn name(value: &str) -> Subject {
        Subject::Name(Username::new(value).expect("valid"))
    }

    fn client(ip: &str) -> ClientInfo {
        ClientInfo::new(Some(ip.parse().expect("valid address")), "")
    }

    fn counted(guard: &LoginGuard, ip: &str) -> u32 {
        let key = ip_key(ip.parse().expect("valid address"));
        lock(&guard.ips)
            .get(&key)
            .map_or(0, |failures| failures.count)
    }

    #[tokio::test]
    async fn a_deleted_account_cannot_be_reserved() {
        let (_, guard) = guard(&AuthConfig::default());
        // Never stored, as if deleted after the sign-in loaded it.
        let error = guard
            .begin(&Subject::User(UserId::generate()))
            .await
            .expect_err("missing");
        assert!(matches!(error, AuthError::NotFound { .. }), "{error:?}");
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
    async fn unknown_usernames_share_a_state_regardless_of_case() {
        let config = AuthConfig::builder()
            .lockout_threshold(2)
            .build()
            .expect("valid");
        let (_, guard) = guard(&config);
        let client = ClientInfo::default();
        let seen = guard.begin(&name("Ghost")).await.expect("granted");
        let first = guard.fail(&client, &name("Ghost"), seen).await;
        assert!(matches!(first, AuthError::InvalidCredentials));
        let seen = guard.begin(&name(" ghost ")).await.expect("granted");
        let second = guard.fail(&client, &name(" ghost "), seen).await;
        assert!(matches!(second, AuthError::AccountLocked { .. }));
        assert!(guard.begin(&name("GHOST")).await.is_err());
        assert!(guard.begin(&name("someone_else")).await.is_ok());
    }

    #[tokio::test]
    async fn running_checks_fill_the_window() {
        let config = AuthConfig::builder()
            .lockout_threshold(2)
            .build()
            .expect("valid");
        let (_, guard) = guard(&config);
        let ghost = name("ghost");
        guard.begin(&ghost).await.expect("first check");
        guard.begin(&ghost).await.expect("second check");
        // Neither check has finished, yet a third is refused before any hashing.
        let error = guard.begin(&ghost).await.expect_err("window full");
        assert_eq!(error.retry_after_secs(), Some(900));
    }

    #[test]
    fn counts_running_attempts_per_ip_and_gives_back_the_successful_ones() {
        let config = AuthConfig::builder()
            .ip_failure_limit(2)
            .build()
            .expect("valid");
        let (_, guard) = guard(&config);
        let attacker = client("203.0.113.7");
        let first = guard.admit(&attacker).expect("first");
        let second = guard.admit(&attacker).expect("second");
        // Two attempts are running: a third is refused although neither has failed yet.
        let error = guard.admit(&attacker).err().expect("over the limit");
        assert_eq!(error.retry_after_secs(), Some(900));
        drop(first);
        assert_eq!(
            counted(&guard, "203.0.113.7"),
            1,
            "a dropped slot is given back"
        );
        second.keep();
        guard.admit(&attacker).expect("room again").keep();
        assert_eq!(counted(&guard, "203.0.113.7"), 2, "kept slots stay counted");
        assert!(guard.admit(&attacker).is_err());
        guard
            .admit(&client("198.51.100.1"))
            .expect("another client")
            .keep();
        guard
            .admit(&ClientInfo::default())
            .expect("no limit")
            .keep();
    }

    #[test]
    fn a_slot_from_an_earlier_window_gives_nothing_back() {
        let (fakes, guard) = guard(&AuthConfig::default());
        let attacker = client("203.0.113.7");
        let old = guard.admit(&attacker).expect("admitted");
        fakes.clock.advance(TimeDelta::minutes(16));
        guard.admit(&attacker).expect("new window").keep();
        drop(old);
        assert_eq!(counted(&guard, "203.0.113.7"), 1);
    }

    #[test]
    fn bounds_the_ip_map() {
        let (fakes, guard) = guard(&AuthConfig::default());
        for index in 0..MAX_ENTRIES {
            let index = u32::try_from(index).expect("small");
            let client = ClientInfo::new(Some(IpAddr::V4(index.into())), "");
            guard.admit(&client).expect("admitted").keep();
        }
        assert_eq!(lock(&guard.ips).len(), MAX_ENTRIES);
        fakes.clock.advance(TimeDelta::minutes(16));
        guard
            .admit(&client("198.51.100.1"))
            .expect("admitted")
            .keep();
        assert_eq!(lock(&guard.ips).len(), 1);
    }
}
