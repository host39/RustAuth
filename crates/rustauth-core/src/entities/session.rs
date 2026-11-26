//! `Session`: one signed-in device.

use std::net::IpAddr;

use chrono::{DateTime, Utc};

use crate::values::{Assurance, AuthMethod, SessionId, TokenHash, UserId};

/// A signed-in device. The bearer token itself is never stored, only its hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Session {
    pub id: SessionId,
    pub user_id: UserId,
    pub token_hash: TokenHash,
    /// How the session was established (`password` in v0.1).
    pub methods: Vec<AuthMethod>,
    pub assurance: Assurance,
    pub created_at: DateTime<Utc>,
    /// Written at most once per touch interval (an hour by default).
    pub last_used_at: DateTime<Utc>,
    /// Slides forward on use, never past `created_at` plus the absolute session lifetime.
    pub expires_at: DateTime<Utc>,
    pub user_agent: String,
    pub ip: Option<IpAddr>,
}

impl Session {
    /// Whether the session still verifies at `now`: before its sliding expiry and before the
    /// absolute limit `max` after creation (which also catches a lowered limit).
    pub fn is_active(&self, now: DateTime<Utc>, max: chrono::TimeDelta) -> bool {
        now < self.expires_at && now < self.created_at + max
    }
}
