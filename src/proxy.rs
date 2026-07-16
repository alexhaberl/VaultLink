use crate::config::{Config, ServerMode};
use http::HeaderMap;
use std::net::{IpAddr, Ipv6Addr};

/// Canonicalizes a TCP peer without widening the configured trust boundary.
///
/// Dual-stack listeners can report an IPv4 peer as an IPv4-mapped IPv6
/// address. Treat that representation as the corresponding IPv4 address, but
/// keep every native IPv6 address exact.
pub fn canonical_peer_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    }
}

/// Returns whether a TCP peer is explicitly present in the proxy allowlist.
pub fn is_trusted_proxy_peer(peer: IpAddr, trusted_proxies: &[IpAddr]) -> bool {
    let peer = canonical_peer_ip(peer);
    trusted_proxies
        .iter()
        .copied()
        .map(canonical_peer_ip)
        .any(|trusted| trusted == peer)
}

/// Returns the stable key used by abuse and concurrency limits.
///
/// IPv6 clients commonly rotate privacy addresses within one delegated prefix,
/// so exact-address keys are trivially bypassed. Group native IPv6 by /64 while
/// preserving IPv4 (including IPv4-mapped IPv6) as an individual address.
pub fn client_limit_key(address: IpAddr) -> IpAddr {
    match canonical_peer_ip(address) {
        IpAddr::V6(address) => {
            let mut segments = address.segments();
            segments[4..].fill(0);
            IpAddr::V6(Ipv6Addr::from(segments))
        }
        address => address,
    }
}

pub fn effective_client_ip(peer: IpAddr, headers: &HeaderMap, config: &Config) -> IpAddr {
    let peer = canonical_peer_ip(peer);
    if config.server.mode != ServerMode::ReverseProxy
        || !config.reverse_proxy.enabled
        || !config.reverse_proxy.trust_x_forwarded_headers
        || !is_trusted_proxy_peer(peer, &config.reverse_proxy.trusted_proxies)
    {
        return peer;
    }

    let mut forwarded = Vec::new();
    for value in headers.get_all("x-forwarded-for") {
        let Ok(value) = value.to_str() else {
            return peer;
        };
        forwarded.extend(value.split(',').map(str::trim));
    }

    let mut current = peer;
    for candidate in forwarded.into_iter().rev() {
        if !is_trusted_proxy_peer(current, &config.reverse_proxy.trusted_proxies) {
            break;
        }
        let Ok(candidate) = candidate.parse() else {
            return peer;
        };
        current = canonical_peer_ip(candidate);
    }
    current
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;
    use std::path::PathBuf;
    fn cfg() -> Config {
        Config {
            server: Server {
                mode: ServerMode::Development,
                listen_address: "127.0.0.1:1".into(),
                public_base_url: "http://localhost:1".into(),
                production_mode: false,
            },
            storage: Storage {
                root_mount_path: PathBuf::from("."),
                data_directory: PathBuf::from("."),
                internal_directory: Some(
                    PathBuf::from(".").join(crate::config::DEFAULT_INTERNAL_DIRECTORY_NAME),
                ),
                require_mount: false,
                external_writers: false,
                allow_external_writer_replace: false,
                expected_filesystem_type: None,
                expected_mount_source: None,
                max_upload_size: 1,
                max_zip_size: 1024,
                max_zip_files: 10,
                max_search_entries: 100,
                max_search_results: 10,
                max_preview_size: 1024,
                preview_extensions: vec!["txt".into()],
                image_preview_extensions: vec!["jpg".into(), "png".into()],
                pdf_preview_enabled: true,
                max_media_preview_size: 1024,
                blocked_extensions: vec![],
            },
            reverse_proxy: ReverseProxy {
                enabled: true,
                allow_non_loopback: false,
                trusted_proxies: vec!["127.0.0.1".parse().unwrap()],
                trust_x_forwarded_headers: true,
            },
            tls: Tls::default(),
            security: Security {
                secure_cookie: false,
                ..Default::default()
            },
            logging: Logging::default(),
        }
    }
    #[test]
    fn ignores_outside_proxy_mode() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
        assert_eq!(
            effective_client_ip("127.0.0.1".parse().unwrap(), &h, &cfg()),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
    }
    #[test]
    fn trusts_only_listed_proxy() {
        let mut c = cfg();
        c.server.mode = ServerMode::ReverseProxy;
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
        assert_eq!(
            effective_client_ip("10.0.0.2".parse().unwrap(), &h, &c),
            "10.0.0.2".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            effective_client_ip("127.0.0.1".parse().unwrap(), &h, &c),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn ignores_attacker_controlled_leftmost_forwarded_value() {
        let mut c = cfg();
        c.server.mode = ServerMode::ReverseProxy;
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            "198.51.100.200, 203.0.113.7".parse().unwrap(),
        );
        assert_eq!(
            effective_client_ip("127.0.0.1".parse().unwrap(), &h, &c),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn walks_right_to_left_through_trusted_proxy_chain() {
        let mut c = cfg();
        c.server.mode = ServerMode::ReverseProxy;
        c.reverse_proxy
            .trusted_proxies
            .push("10.0.0.2".parse().unwrap());
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.7, 10.0.0.2".parse().unwrap());
        assert_eq!(
            effective_client_ip("127.0.0.1".parse().unwrap(), &h, &c),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn stops_before_untrusted_forwarded_hops() {
        let mut c = cfg();
        c.server.mode = ServerMode::ReverseProxy;
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "not-an-ip, 203.0.113.7".parse().unwrap());
        assert_eq!(
            effective_client_ip("127.0.0.1".parse().unwrap(), &h, &c),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn malformed_relevant_forwarded_hop_falls_back_to_peer() {
        let mut c = cfg();
        c.server.mode = ServerMode::ReverseProxy;
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "not-an-ip".parse().unwrap());
        assert_eq!(
            effective_client_ip("127.0.0.1".parse().unwrap(), &h, &c),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn limiter_keys_group_ipv6_privacy_addresses_by_prefix() {
        assert_eq!(
            client_limit_key("2001:db8:1234:5678::1".parse().unwrap()),
            client_limit_key("2001:db8:1234:5678:ffff::2".parse().unwrap())
        );
        assert_ne!(
            client_limit_key("2001:db8:1234:5678::1".parse().unwrap()),
            client_limit_key("2001:db8:1234:5679::1".parse().unwrap())
        );
        assert_eq!(
            client_limit_key("::ffff:192.0.2.7".parse().unwrap()),
            "192.0.2.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn proxy_peer_comparison_canonicalizes_mapped_ipv4_but_keeps_ipv6_exact() {
        let trusted = vec!["192.0.2.7".parse().unwrap(), "2001:db8::1".parse().unwrap()];
        assert!(is_trusted_proxy_peer(
            "::ffff:192.0.2.7".parse().unwrap(),
            &trusted
        ));
        assert!(!is_trusted_proxy_peer(
            "2001:db8::2".parse().unwrap(),
            &trusted
        ));
    }

    #[test]
    fn forwarded_headers_accept_a_canonical_mapped_proxy_peer() {
        let mut c = cfg();
        c.server.mode = ServerMode::ReverseProxy;
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.7".parse().unwrap());
        assert_eq!(
            effective_client_ip("::ffff:127.0.0.1".parse().unwrap(), &h, &c),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
    }
}
