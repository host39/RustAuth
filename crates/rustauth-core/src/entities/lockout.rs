//! `Lockout`: the failed sign-in state of an account or of a username without one, the
//! [`Subject`] it belongs to, and the [`Reservation`] a password check starts with.

use chrono::{DateTime, Utc};

use crate::values::{UserId, Username};

/// Failed sign-in state. Accounts keep it on `auth.users`; a username without an account keeps
/// the same state in the same storage (see [`Subject`]), so both behave the same. See
/// "Brute-Force Protection" in the design.
///
/// The transitions ([`Lockout::reserve`], [`Lockout::fail`], [`Lockout::lock`]) and the
/// conditions the repositories apply ([`Lockout::holds`], [`Lockout::is_stale`]) are defined
/// here so every store applies the same rules; the Postgres adapter performs each step
/// atomically in SQL.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Lockout {
    /// Failures in the current window, password checks still running included (a check counts
    /// as a failure from the moment it is reserved until its password proves right).
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

    /// Failures that still count at the start of the window, `since`.
    pub fn failures(&self, since: DateTime<Utc>) -> u32 {
        match self.last_failed_at {
            Some(last) if last >= since => self.failed_count,
            _ => 0,
        }
    }

    /// Starts a password check at `at`: refused while locked or while the window (from `since`)
    /// already holds `threshold` failures, finished or still running; otherwise counted as a
    /// failure ([`Lockout::fail`]) until the password proves right. Taking this step atomically
    /// is what keeps concurrent attempts from getting around the threshold.
    #[must_use]
    pub fn reserve(self, at: DateTime<Utc>, since: DateTime<Utc>, threshold: u32) -> Reservation {
        if self.locked(at).is_some() || self.failures(since) >= threshold {
            Reservation::Refused(self)
        } else {
            Reservation::Granted(self.fail(at, since))
        }
    }

    /// Records one wrong password at `at`. A previous failure before `since` (the start of the
    /// failure window) no longer counts, so the count starts again at one.
    #[must_use]
    pub fn fail(self, at: DateTime<Utc>, since: DateTime<Utc>) -> Self {
        Self {
            failed_count: self.failures(since).saturating_add(1),
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

    /// Whether this stored state still holds the failures counted in `seen` (the state a
    /// reservation returned): nobody locked, unlocked, or signed in since. Only then does a
    /// failure that reached the threshold lock, so concurrent failures lock once and a correct
    /// password that finished first is not undone.
    pub fn holds(&self, seen: &Lockout) -> bool {
        self.lockouts == seen.lockouts && self.failed_count >= seen.failed_count
    }

    /// Whether the state no longer matters at the window start `since`: never locked and no
    /// failure inside the window, so it behaves exactly like no state at all. Stores delete such
    /// states of usernames without an account.
    pub fn is_stale(&self, since: DateTime<Utc>) -> bool {
        self.lockouts == 0 && self.locked_until.is_none() && self.failures(since) == 0
    }

    /// Whether there is anything to reset after a successful sign-in.
    pub fn is_clear(&self) -> bool {
        *self == Self::default()
    }
}

/// Whose failed sign-ins a [`Lockout`] counts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Subject {
    /// An existing account: its state is stored with the account.
    User(UserId),
    /// A username without an account, keyed by its lowercase form ([`Username::canonical`]) in
    /// the same storage, so it locks exactly like a real account (on every instance and across
    /// restarts) and lockout cannot reveal which usernames exist. Input that is not a valid
    /// username is never tracked: no account can have it, so it could only collide with one.
    Name(Username),
}

/// The outcome of [`Lockout::reserve`] (and of `UserRepository::reserve`, which applies it).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reservation {
    /// The password check may run. It already counts as a failure; this is the new state.
    Granted(Lockout),
    /// Locked, or the window is full: no check runs and nothing changed. This is the stored
    /// state.
    Refused(Lockout),
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
        assert_eq!(lockout.failures(at(-5)), 3);
        assert_eq!(lockout.failures(at(11)), 0);
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

    #[test]
    fn reserves_checks_up_to_the_threshold() {
        let mut lockout = Lockout::default();
        for count in 1..=3 {
            match lockout.reserve(at(0), at(-15), 3) {
                Reservation::Granted(next) => {
                    assert_eq!(next.failed_count, count);
                    lockout = next;
                }
                Reservation::Refused(_) => panic!("check {count} refused"),
            }
        }
        // Three checks are counted (finished or not): a fourth is refused and changes nothing.
        assert_eq!(
            lockout.reserve(at(1), at(-14), 3),
            Reservation::Refused(lockout)
        );
        // Once the window has passed, checks start again.
        assert!(matches!(
            lockout.reserve(at(16), at(1), 3),
            Reservation::Granted(Lockout {
                failed_count: 1,
                ..
            })
        ));
    }

    #[test]
    fn refuses_checks_while_locked() {
        let locked = Lockout::default().lock(at(15));
        assert_eq!(
            locked.reserve(at(14), at(-1), 5),
            Reservation::Refused(locked)
        );
        assert!(matches!(
            locked.reserve(at(15), at(0), 5),
            Reservation::Granted(_)
        ));
    }

    #[test]
    fn holds_until_someone_locks_unlocks_or_signs_in() {
        let seen = Lockout {
            failed_count: 5,
            last_failed_at: Some(at(0)),
            ..Lockout::default()
        };
        assert!(seen.holds(&seen));
        assert!(seen.fail(at(1), at(-14)).holds(&seen));
        assert!(!seen.lock(at(15)).holds(&seen), "locked by another failure");
        assert!(!Lockout::default().holds(&seen), "reset by a sign-in");
    }

    #[test]
    fn only_never_locked_states_outside_the_window_are_stale() {
        let failed = Lockout::default().fail(at(0), at(-15));
        assert!(!failed.is_stale(at(-15)));
        assert!(failed.is_stale(at(1)));
        let locked = failed.lock(at(15));
        assert!(!locked.is_stale(at(30)), "keeps doubling the next lock");
        assert!(Lockout::default().is_stale(at(0)));
    }
}
