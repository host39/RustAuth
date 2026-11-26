//! `FakeClock`: a clock that only moves when told to.

use std::sync::{Mutex, PoisonError};

use chrono::{DateTime, TimeDelta, Utc};

use crate::ports::Clock;

#[derive(Debug)]
pub struct FakeClock {
    now: Mutex<DateTime<Utc>>,
}

impl FakeClock {
    /// The default start: 2026-01-01T00:00:00Z.
    pub const START: DateTime<Utc> = DateTime::from_timestamp_nanos(1_767_225_600_000_000_000);

    pub fn new(start: DateTime<Utc>) -> Self {
        Self {
            now: Mutex::new(start),
        }
    }

    pub fn advance(&self, by: TimeDelta) {
        let mut now = self.now.lock().unwrap_or_else(PoisonError::into_inner);
        *now += by;
    }

    pub fn set(&self, at: DateTime<Utc>) {
        *self.now.lock().unwrap_or_else(PoisonError::into_inner) = at;
    }
}

impl Default for FakeClock {
    fn default() -> Self {
        Self::new(Self::START)
    }
}

impl Clock for FakeClock {
    fn now(&self) -> DateTime<Utc> {
        *self.now.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn moves_only_when_told() {
        let clock = FakeClock::default();
        assert_eq!(clock.now().to_rfc3339(), "2026-01-01T00:00:00+00:00");
        clock.advance(TimeDelta::minutes(90));
        assert_eq!(clock.now(), FakeClock::START + TimeDelta::minutes(90));
        clock.set(FakeClock::START);
        assert_eq!(clock.now(), FakeClock::START);
    }
}
