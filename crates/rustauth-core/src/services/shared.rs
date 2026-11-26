//! Helpers shared by the in-memory limiters.

use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Mutex, MutexGuard, PoisonError};

use chrono::{DateTime, Utc};

/// Most keys an in-memory limiter keeps before it prunes, so a flood of distinct usernames or
/// addresses cannot grow memory without bound.
pub(crate) const MAX_ENTRIES: usize = 10_000;

/// The key per-IP limits count under. IPv6 clients are grouped by their /64 prefix, because a
/// single host usually controls a whole /64.
pub(crate) fn ip_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(ip) => {
            let [a, b, c, d, ..] = ip.segments();
            IpAddr::V6(Ipv6Addr::new(a, b, c, d, 0, 0, 0, 0))
        }
        ip => ip,
    }
}

/// Whole seconds from `now` until `until`, rounded up and at least one (for `Retry-After`).
pub(crate) fn seconds_until(now: DateTime<Utc>, until: DateTime<Utc>) -> u64 {
    let millis = (until - now).num_milliseconds().max(0).unsigned_abs();
    millis.div_ceil(1000).max(1)
}

/// Locks a limiter map. The critical sections never panic, so a poisoned lock still holds
/// consistent data and is used as is.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use chrono::TimeDelta;

    use super::*;

    #[test]
    fn groups_ipv6_by_64_prefix() {
        let first: IpAddr = "2001:db8:1:2:aaaa::1".parse().expect("valid");
        let second: IpAddr = "2001:db8:1:2:bbbb::2".parse().expect("valid");
        let other: IpAddr = "2001:db8:1:3::1".parse().expect("valid");
        assert_eq!(ip_key(first), ip_key(second));
        assert_ne!(ip_key(first), ip_key(other));
        let v4: IpAddr = "192.0.2.1".parse().expect("valid");
        assert_eq!(ip_key(v4), v4);
    }

    #[test]
    fn rounds_waits_up_to_whole_seconds() {
        let now = DateTime::UNIX_EPOCH;
        assert_eq!(seconds_until(now, now + TimeDelta::milliseconds(1500)), 2);
        assert_eq!(seconds_until(now, now + TimeDelta::seconds(60)), 60);
        assert_eq!(seconds_until(now, now), 1);
        assert_eq!(seconds_until(now, now - TimeDelta::seconds(5)), 1);
    }
}
