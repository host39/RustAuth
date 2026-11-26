//! `IpRange`: a single address or a CIDR block, for `AUTH_TRUSTED_PROXIES`.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use crate::error::AuthError;

/// An IP address or CIDR block (`10.0.0.0/8`, `fd00::/8`, `192.0.2.7`). Host bits are cleared,
/// so `10.1.2.3/8` is the same range as `10.0.0.0/8`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct IpRange {
    network: IpAddr,
    prefix: u8,
}

impl IpRange {
    /// Whether `ip` lies in the range. IPv4-mapped IPv6 addresses match IPv4 ranges.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip.to_canonical()) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                mask4(u32::from(ip), self.prefix) == u32::from(network)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                mask6(u128::from(ip), self.prefix) == u128::from(network)
            }
            _ => false,
        }
    }

    pub fn network(&self) -> IpAddr {
        self.network
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }
}

/// Keeps the first `prefix` bits. A shift by the full width (prefix 0) yields zero.
fn mask4(bits: u32, prefix: u8) -> u32 {
    let shift = 32 - u32::from(prefix);
    bits.checked_shr(shift)
        .and_then(|kept| kept.checked_shl(shift))
        .unwrap_or(0)
}

fn mask6(bits: u128, prefix: u8) -> u128 {
    let shift = 128 - u32::from(prefix);
    bits.checked_shr(shift)
        .and_then(|kept| kept.checked_shl(shift))
        .unwrap_or(0)
}

impl FromStr for IpRange {
    type Err = AuthError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let invalid = || {
            AuthError::validation(
                "trustedProxies",
                "Trusted proxies must be IP addresses or CIDR blocks.",
            )
        };
        let (address, prefix) = match value.trim().split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (value.trim(), None),
        };
        let address: IpAddr = address.parse().map_err(|_| invalid())?;
        let address = address.to_canonical();
        let max = if address.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(prefix) => prefix.parse::<u8>().map_err(|_| invalid())?,
            None => max,
        };
        if prefix > max {
            return Err(invalid());
        }
        let network = match address {
            IpAddr::V4(ip) => IpAddr::V4(mask4(u32::from(ip), prefix).into()),
            IpAddr::V6(ip) => IpAddr::V6(mask6(u128::from(ip), prefix).into()),
        };
        Ok(Self { network, prefix })
    }
}

impl fmt::Display for IpRange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.network, self.prefix)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("valid address")
    }

    fn range(value: &str) -> IpRange {
        value.parse().expect("valid range")
    }

    #[test]
    fn matches_ipv4_blocks() {
        let private = range("10.0.0.0/8");
        assert!(private.contains(ip("10.200.3.4")));
        assert!(!private.contains(ip("11.0.0.1")));
        assert!(range("0.0.0.0/0").contains(ip("203.0.113.9")));
        assert_eq!(range("10.1.2.3/8"), private);
        assert_eq!(private.to_string(), "10.0.0.0/8");
    }

    #[test]
    fn treats_a_bare_address_as_a_single_host() {
        let host = range("192.0.2.7");
        assert_eq!(host.prefix(), 32);
        assert!(host.contains(ip("192.0.2.7")));
        assert!(!host.contains(ip("192.0.2.8")));
    }

    #[test]
    fn matches_ipv6_blocks() {
        let unique_local = range("fd00::/8");
        assert!(unique_local.contains(ip("fd12:3456::1")));
        assert!(!unique_local.contains(ip("fe80::1")));
        assert!(range("::1").contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(range("::/0").contains(ip("2001:db8::1")));
    }

    #[test]
    fn matches_mapped_ipv4_against_ipv4_blocks() {
        let mapped = IpAddr::V6(Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped());
        assert!(range("10.0.0.0/8").contains(mapped));
        assert!(!range("10.0.0.0/8").contains(ip("::1")));
    }

    #[test]
    fn rejects_invalid_ranges() {
        for value in [
            "",
            "10.0.0.0/33",
            "::/129",
            "10.0.0/8",
            "proxy.local",
            "10.0.0.0/x",
        ] {
            assert!(value.parse::<IpRange>().is_err(), "{value}");
        }
    }
}
