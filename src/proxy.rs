use crate::config::{Config, ServerMode};
use http::HeaderMap;
use std::net::IpAddr;

pub fn effective_client_ip(peer: IpAddr, headers: &HeaderMap, config: &Config) -> IpAddr {
    if config.server.mode != ServerMode::ReverseProxy
        || !config.reverse_proxy.enabled
        || !config.reverse_proxy.trust_x_forwarded_headers
        || !config.reverse_proxy.trusted_proxies.contains(&peer)
    {
        return peer;
    }
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(peer)
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
                max_upload_size: 1,
                max_zip_size: 1024,
                max_zip_files: 10,
                max_search_entries: 100,
                max_search_results: 10,
                max_preview_size: 1024,
                preview_extensions: vec!["txt".into()],
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
}
