//! `Lockout`: an account's failed sign-in state.

use chrono::{DateTime, Utc};

/// Failed sign-in state, persisted on `auth.users` for real accounts and kept in memory for
/// unknown usernames (so both behave the same). See "Brute-Force Protection" in the design.
///
/// The transitions ([`Lockout::fail`], [`Lockout::lock`]) are defined here so every store applies
/// the same rules; the Postgres adapter performs the same `fail` step atomically in SQL.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Lockout {
    /// Wrong passwords in the current window.
    pub failed_count: u32,
    /// Consecutive lockouts since the last successful sign-in; each one doubles the next duration.
    pub lockouts: u32,
    pub last_failed_at: Option<DateTime<Utc>>,
    /// Sign-in is refused until this time, even with the correct password.
    pub locked_until: Option<DateTime<Utc>>,
}

impl Lockout {
    /// The end of the lock, if the account is locked at `now`.
    pub fn locked(&self, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        self.locked_until.filter(|until| *until > now)
    }

    /// Records one wrong password at `at`. A previous failure before `since` (the start of the
    /// failure window) no longer counts, so the count starts again at one.
    #[must_use]
    pub fn fail(self, at: DateTime<Utc>, since: DateTime<Utc>) -> Self {
        let fresh = self.last_failed_at.is_none_or(|last| last < since);
        Self {
            failed_count: if fresh {
                1
            } else {
                self.failed_count.saturating_add(1)
            },
            last_failed_at: Some(at),
            ..self
        }
    }

    /// Locks until `until`: the failure count starts over and the lockout counter goes up.
    #[must_use]
    pub fn lock(self, until: DateTime<Utc>) -> Self {
        Self {
            failed_count: 0,
            lockouts: self.lockouts.saturating_add(1),
            locked_until: Some(until),
            ..self
        }
    }

    /// Whether there is anything to reset after a successful sign-in.
    pub fn is_clear(&self) -> bool {
        *self == Self::default()
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeDelta;

    use super::*;

    fn at(minutes: i64) -> DateTime<Utc> {
        DateTime::UNIX_EPOCH + TimeDelta::minutes(minutes)
    }

    #[test]
    fn counts_failures_inside_the_window() {
        let lockout = Lockout::default()
            .fail(at(0), at(-15))
            .fail(at(5), at(-10))
            .fail(at(10), at(-5));
        assert_eq!(lockout.failed_count, 3);
        assert_eq!(lockout.last_failed_at, Some(at(10)));
    }

    #[test]
    fn starts_over_after_the_window() {
        let lockout = Lockout::default()
            .fail(at(0), at(-15))
            .fail(at(1), at(-14))
            .fail(at(20), at(5));
        assert_eq!(lockout.failed_count, 1);
    }

    #[test]
    fn locking_resets_the_count_and_counts_the_lockout() {
        let lockout = Lockout {
            failed_count: 5,
            ..Lockout::default()
        }
        .lock(at(15));
        assert_eq!(lockout.failed_count, 0);
        assert_eq!(lockout.lockouts, 1);
        assert_eq!(lockout.locked(at(14)), Some(at(15)));
        assert_eq!(lockout.locked(at(15)), None);
        assert!(!lockout.is_clear());
        assert!(Lockout::default().is_clear());
    }
}
