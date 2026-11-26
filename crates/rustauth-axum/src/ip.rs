//! Client IP: the peer address from `ConnectInfo`, or, when the peer is a trusted proxy, the
//! nearest `X-Forwarded-For` hop that is not one.
//!
//! The hops are read from right to left (nearest first), because each proxy appends the address
//! it saw. Every hop left of the first untrusted one could have been written by the client, so
//! it is ignored. Per-IP limits key on the result.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};

use axum::extract::ConnectInfo;
use axum::http::{Extensions, HeaderMap, HeaderName};
use rustauth_core::{ClientInfo, IpRange};

const FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");

/// Whether the missing `ConnectInfo` warning was logged already (once per process).
static WARNED: AtomicBool = AtomicBool::new(false);

/// The client address of a request that arrived from `peer`. When `peer` lies in one of
/// `proxies`, the `X-Forwarded-For` hops are walked from the right while they are trusted
/// proxies as well; the first untrusted hop is the client. If every hop is trusted, the
/// left-most one is. A malformed hop ends the walk at the last address read. Without a peer
/// address the client is unknown (`None`).
pub fn client_ip(peer: Option<IpAddr>, headers: &HeaderMap, proxies: &[IpRange]) -> Option<IpAddr> {
    let mut client = peer?.to_canonical();
    if !trusted(client, proxies) {
        return Some(client);
    }
    let hops: Vec<&str> = headers
        .get_all(FORWARDED_FOR)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .collect();
    for hop in hops.into_iter().rev() {
        let Some(ip) = parse(hop) else {
            break;
        };
        client = ip;
        if !trusted(ip, proxies) {
            break;
        }
    }
    Some(client)
}

/// Where a request came from: [`client_ip`] for the peer in `ConnectInfo<SocketAddr>` and the
/// `User-Agent` header.
///
/// The peer is known only when the server runs with
/// `into_make_service_with_connect_info::<SocketAddr>()`. Without it per-IP limits are off, which
/// is logged once (`rustauth.client.peer-unknown`).
pub fn client_info(
    extensions: &Extensions,
    headers: &HeaderMap,
    proxies: &[IpRange],
) -> ClientInfo {
    let peer = extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(address)| address.ip());
    if peer.is_none() && !WARNED.swap(true, Ordering::Relaxed) {
        tracing::warn!("rustauth.client.peer-unknown");
    }
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .map(|value| String::from_utf8_lossy(value.as_bytes()))
        .unwrap_or_default();
    ClientInfo::new(client_ip(peer, headers, proxies), &user_agent)
}

fn trusted(ip: IpAddr, proxies: &[IpRange]) -> bool {
    proxies.iter().any(|range| range.contains(ip))
}

/// One hop: an address, optionally with a port (`192.0.2.1:443`, `[2001:db8::1]:443`).
fn parse(hop: &str) -> Option<IpAddr> {
    let hop = hop.trim();
    hop.parse::<IpAddr>()
        .or_else(|_| hop.parse::<SocketAddr>().map(|address| address.ip()))
        .ok()
        .map(|ip| ip.to_canonical())
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("valid address")
    }

    fn proxies(values: &[&str]) -> Vec<IpRange> {
        values
            .iter()
            .map(|value| value.parse().expect("valid range"))
            .collect()
    }

    fn forwarded(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(
                FORWARDED_FOR,
                HeaderValue::from_str(value).expect("valid header"),
            );
        }
        headers
    }

    #[test]
    fn uses_an_untrusted_peer_and_ignores_its_header() {
        let headers = forwarded(&["198.51.100.1"]);
        let resolved = client_ip(Some(ip("203.0.113.9")), &headers, &proxies(&["10.0.0.0/8"]));
        assert_eq!(resolved, Some(ip("203.0.113.9")));
        assert_eq!(
            client_ip(Some(ip("10.0.0.2")), &headers, &[]),
            Some(ip("10.0.0.2"))
        );
    }

    #[test]
    fn takes_the_nearest_untrusted_hop_behind_trusted_proxies() {
        // The client forged the first entry; the proxy chain appended the rest.
        let headers = forwarded(&["192.0.2.66, 198.51.100.7, 10.0.0.5"]);
        let resolved = client_ip(Some(ip("10.0.0.1")), &headers, &proxies(&["10.0.0.0/8"]));
        assert_eq!(resolved, Some(ip("198.51.100.7")));
    }

    #[test]
    fn reads_repeated_headers_in_order() {
        let headers = forwarded(&["192.0.2.66, 198.51.100.7", "10.0.0.5"]);
        let resolved = client_ip(Some(ip("10.0.0.1")), &headers, &proxies(&["10.0.0.0/8"]));
        assert_eq!(resolved, Some(ip("198.51.100.7")));
    }

    #[test]
    fn falls_back_to_the_left_most_hop_when_every_hop_is_trusted() {
        let headers = forwarded(&["10.0.0.9, 10.0.0.5"]);
        let resolved = client_ip(Some(ip("10.0.0.1")), &headers, &proxies(&["10.0.0.0/8"]));
        assert_eq!(resolved, Some(ip("10.0.0.9")));
    }

    #[test]
    fn keeps_the_proxy_without_a_header() {
        let resolved = client_ip(
            Some(ip("10.0.0.1")),
            &HeaderMap::new(),
            &proxies(&["10.0.0.0/8"]),
        );
        assert_eq!(resolved, Some(ip("10.0.0.1")));
    }

    #[test]
    fn stops_at_a_malformed_hop() {
        let headers = forwarded(&["198.51.100.7, unknown, 10.0.0.5"]);
        let resolved = client_ip(Some(ip("10.0.0.1")), &headers, &proxies(&["10.0.0.0/8"]));
        assert_eq!(resolved, Some(ip("10.0.0.5")));
    }

    #[test]
    fn accepts_ports_and_mapped_addresses() {
        let headers = forwarded(&["[2001:db8::7]:443, 198.51.100.7:8080"]);
        let trusted = proxies(&["10.0.0.0/8", "198.51.100.7"]);
        let peer = IpAddr::V6(std::net::Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped());
        assert_eq!(
            client_ip(Some(peer), &headers, &trusted),
            Some(ip("2001:db8::7"))
        );
    }

    #[test]
    fn without_a_peer_the_client_is_unknown() {
        let headers = forwarded(&["198.51.100.7"]);
        assert_eq!(client_ip(None, &headers, &proxies(&["0.0.0.0/0"])), None);
    }

    #[test]
    fn client_info_reads_connect_info_and_the_user_agent() {
        let mut extensions = Extensions::new();
        extensions.insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 9], 50_000))));
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::USER_AGENT,
            HeaderValue::from_static("example-agent/1.0"),
        );
        let client = client_info(&extensions, &headers, &[]);
        assert_eq!(client.ip(), Some(ip("203.0.113.9")));
        assert_eq!(client.user_agent(), "example-agent/1.0");
        assert_eq!(client_info(&Extensions::new(), &headers, &[]).ip(), None);
    }
}
