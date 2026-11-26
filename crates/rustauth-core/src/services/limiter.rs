//! `RateLimiter`: in-memory token buckets per client IP for the public auth routes.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};

use crate::error::{AuthError, AuthResult};
use crate::ports::Clock;
use crate::services::shared::{MAX_ENTRIES, ip_key, lock};

/// One client's bucket: `tokens` as of `updated`.
#[derive(Clone, Copy, Debug)]
struct Bucket {
    tokens: f64,
    updated: DateTime<Utc>,
}

impl Bucket {
    /// Tokens at `now`, refilled at `rate` per second up to `capacity`.
    fn level(&self, now: DateTime<Utc>, rate: f64, capacity: f64) -> f64 {
        let elapsed = (now - self.updated).num_milliseconds().max(0) as f64 / 1000.0;
        (self.tokens + elapsed * rate).min(capacity)
    }
}

/// Allows `per_minute` requests per client IP per minute, with bursts up to `per_minute`. The
/// HTTP adapter calls [`RateLimiter::check`] on `/auth/login`, `/auth/register`, and
/// `/auth/setup`. IPv6 clients share a bucket per /64 prefix.
pub struct RateLimiter {
    clock: Arc<dyn Clock>,
    capacity: f64,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl RateLimiter {
    pub fn new(clock: Arc<dyn Clock>, per_minute: u32) -> Self {
        Self {
            clock,
            capacity: f64::from(per_minute.max(1)),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Takes one token for `ip`, or fails with `RateLimited` and the wait until the next one.
    /// Requests without a known IP are not limited.
    pub fn check(&self, ip: Option<IpAddr>) -> AuthResult<()> {
        let Some(ip) = ip else {
            return Ok(());
        };
        let now = self.clock.now();
        let capacity = self.capacity;
        let rate = capacity / 60.0;
        let key = ip_key(ip);
        let mut buckets = lock(&self.buckets);
        if !buckets.contains_key(&key) && buckets.len() >= MAX_ENTRIES {
            // A full bucket behaves like a missing one, so idle clients can go.
            buckets.retain(|_, bucket| bucket.level(now, rate, capacity) < capacity);
            if buckets.len() >= MAX_ENTRIES
                && let Some(oldest) = buckets
                    .iter()
                    .min_by_key(|(_, bucket)| bucket.updated)
                    .map(|(ip, _)| *ip)
            {
                buckets.remove(&oldest);
            }
        }
        let bucket = buckets.entry(key).or_insert(Bucket {
            tokens: capacity,
            updated: now,
        });
        let tokens = bucket.level(now, rate, capacity);
        bucket.updated = now;
        if tokens >= 1.0 {
            bucket.tokens = tokens - 1.0;
            Ok(())
        } else {
            bucket.tokens = tokens;
            let wait = ((1.0 - tokens) / rate).ceil().max(1.0);
            Err(AuthError::RateLimited {
                retry_after_secs: wait as u64,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeDelta;

    use super::*;
    use crate::testing::FakeClock;

    fn ip(value: &str) -> Option<IpAddr> {
        Some(value.parse().expect("valid address"))
    }

    fn limiter(per_minute: u32) -> (Arc<FakeClock>, RateLimiter) {
        let clock = Arc::new(FakeClock::default());
        let limiter = RateLimiter::new(clock.clone(), per_minute);
        (clock, limiter)
    }

    #[test]
    fn allows_a_burst_then_refuses_with_retry_after() {
        let (_, limiter) = limiter(60);
        for _ in 0..60 {
            limiter.check(ip("192.0.2.1")).expect("within the limit");
        }
        let error = limiter.check(ip("192.0.2.1")).expect_err("over the limit");
        assert!(matches!(
            error,
            AuthError::RateLimited {
                retry_after_secs: 1
            }
        ));
    }

    #[test]
    fn refills_over_time() {
        let (clock, limiter) = limiter(6);
        for _ in 0..6 {
            limiter.check(ip("192.0.2.1")).expect("within the limit");
        }
        let error = limiter.check(ip("192.0.2.1")).expect_err("empty");
        assert_eq!(error.retry_after_secs(), Some(10));
        clock.advance(TimeDelta::seconds(10));
        limiter.check(ip("192.0.2.1")).expect("one token refilled");
        assert!(limiter.check(ip("192.0.2.1")).is_err());
        clock.advance(TimeDelta::minutes(5));
        for _ in 0..6 {
            limiter
                .check(ip("192.0.2.1"))
                .expect("refilled to capacity, not beyond");
        }
        assert!(limiter.check(ip("192.0.2.1")).is_err());
    }

    #[test]
    fn keeps_clients_apart() {
        let (_, limiter) = limiter(1);
        limiter.check(ip("192.0.2.1")).expect("first client");
        assert!(limiter.check(ip("192.0.2.1")).is_err());
        limiter.check(ip("192.0.2.2")).expect("second client");
        limiter
            .check(None)
            .expect("unknown clients are not limited");
        limiter
            .check(None)
            .expect("unknown clients are not limited");
    }

    #[test]
    fn groups_an_ipv6_64() {
        let (_, limiter) = limiter(1);
        limiter.check(ip("2001:db8::1")).expect("first address");
        assert!(limiter.check(ip("2001:db8::2")).is_err());
        limiter.check(ip("2001:db8:0:1::1")).expect("another /64");
    }

    #[test]
    fn bounds_the_bucket_map() {
        let (clock, limiter) = limiter(60);
        for index in 0..MAX_ENTRIES {
            let index = u32::try_from(index).expect("small");
            limiter
                .check(Some(IpAddr::V4(index.into())))
                .expect("fresh bucket");
        }
        assert_eq!(lock(&limiter.buckets).len(), MAX_ENTRIES);
        clock.advance(TimeDelta::minutes(1));
        limiter.check(ip("198.51.100.1")).expect("fresh bucket");
        assert_eq!(lock(&limiter.buckets).len(), 1);
    }
}
