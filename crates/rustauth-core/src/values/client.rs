//! `ClientInfo`: where a request came from.

use std::net::IpAddr;

/// The client IP (after trusted-proxy resolution in the HTTP adapter) and the first 256
/// characters of the user agent. Recorded on sessions and used for per-IP limits.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ClientInfo {
    ip: Option<IpAddr>,
    user_agent: String,
}

impl ClientInfo {
    pub const USER_AGENT_MAX_CHARS: usize = 256;

    /// IPv4-mapped IPv6 addresses (`::ffff:192.0.2.1`) are stored as plain IPv4.
    pub fn new(ip: Option<IpAddr>, user_agent: &str) -> Self {
        Self {
            ip: ip.map(|ip| ip.to_canonical()),
            user_agent: user_agent
                .chars()
                .take(Self::USER_AGENT_MAX_CHARS)
                .collect(),
        }
    }

    /// `None` when the adapter could not tell (no peer address); per-IP limits then do not apply.
    pub fn ip(&self) -> Option<IpAddr> {
        self.ip
    }

    pub fn user_agent(&self) -> &str {
        &self.user_agent
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn keeps_the_first_256_characters_of_the_user_agent() {
        let client = ClientInfo::new(None, &"é".repeat(300));
        assert_eq!(client.user_agent().chars().count(), 256);
        assert_eq!(ClientInfo::new(None, "curl/8").user_agent(), "curl/8");
    }

    #[test]
    fn stores_mapped_ipv4_as_ipv4() {
        let mapped = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped());
        let client = ClientInfo::new(Some(mapped), "");
        assert_eq!(client.ip(), Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(ClientInfo::new(Some(v6), "").ip(), Some(v6));
    }
}
