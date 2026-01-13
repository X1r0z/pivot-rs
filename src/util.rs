use anyhow::Result;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::crypto;

#[derive(Clone, Debug)]
pub struct Endpoint {
    pub addr: String,
    pub tls: bool,
}

impl Endpoint {
    pub fn new(addr: String, tls: bool) -> Self {
        Self { addr, tls }
    }
}

pub fn generate_random_string(length: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

pub fn parse_addrs(addrs: Vec<String>) -> Vec<Endpoint> {
    addrs
        .into_iter()
        .map(|raw| {
            let tls = raw.starts_with('+');
            let clean = raw.trim_start_matches('+');
            let addr = if clean.contains(':') {
                clean.to_string()
            } else {
                format!("0.0.0.0:{clean}")
            };
            Endpoint::new(addr, tls)
        })
        .collect()
}

pub fn parse_addr(addr: Option<String>) -> Option<Endpoint> {
    addr.map(|a| parse_addrs(vec![a]).pop().unwrap())
}

pub fn make_tls_acceptor(ep: &Endpoint) -> Result<Option<TlsAcceptor>> {
    if ep.tls {
        Ok(Some(crypto::get_tls_acceptor(&ep.addr)?))
    } else {
        Ok(None)
    }
}

pub fn make_tls_connector(ep: &Endpoint) -> Option<TlsConnector> {
    if ep.tls {
        Some(crypto::get_tls_connector())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_new() {
        let ep = Endpoint::new("127.0.0.1:8080".to_string(), true);
        assert_eq!(ep.addr, "127.0.0.1:8080");
        assert!(ep.tls);

        let ep = Endpoint::new("0.0.0.0:9999".to_string(), false);
        assert_eq!(ep.addr, "0.0.0.0:9999");
        assert!(!ep.tls);
    }

    #[test]
    fn test_generate_random_string() {
        let s1 = generate_random_string(12);
        let s2 = generate_random_string(12);

        assert_eq!(s1.len(), 12);
        assert_eq!(s2.len(), 12);
        assert_ne!(s1, s2);

        assert!(s1.chars().all(|c| c.is_ascii_alphanumeric()));

        let s3 = generate_random_string(0);
        assert!(s3.is_empty());

        let s4 = generate_random_string(100);
        assert_eq!(s4.len(), 100);
    }

    #[test]
    fn test_parse_addrs_with_port_only() {
        let addrs = vec!["8080".to_string()];
        let endpoints = parse_addrs(addrs);

        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].addr, "0.0.0.0:8080");
        assert!(!endpoints[0].tls);
    }

    #[test]
    fn test_parse_addrs_with_ip_and_port() {
        let addrs = vec!["127.0.0.1:8080".to_string()];
        let endpoints = parse_addrs(addrs);

        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].addr, "127.0.0.1:8080");
        assert!(!endpoints[0].tls);
    }

    #[test]
    fn test_parse_addrs_with_tls_prefix() {
        let addrs = vec!["+8080".to_string()];
        let endpoints = parse_addrs(addrs);

        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].addr, "0.0.0.0:8080");
        assert!(endpoints[0].tls);
    }

    #[test]
    fn test_parse_addrs_with_tls_and_ip() {
        let addrs = vec!["+192.168.1.1:443".to_string()];
        let endpoints = parse_addrs(addrs);

        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].addr, "192.168.1.1:443");
        assert!(endpoints[0].tls);
    }

    #[test]
    fn test_parse_addrs_multiple() {
        let addrs = vec![
            "8080".to_string(),
            "+9090".to_string(),
            "10.0.0.1:3389".to_string(),
            "+vps.example.com:7777".to_string(),
        ];
        let endpoints = parse_addrs(addrs);

        assert_eq!(endpoints.len(), 4);

        assert_eq!(endpoints[0].addr, "0.0.0.0:8080");
        assert!(!endpoints[0].tls);

        assert_eq!(endpoints[1].addr, "0.0.0.0:9090");
        assert!(endpoints[1].tls);

        assert_eq!(endpoints[2].addr, "10.0.0.1:3389");
        assert!(!endpoints[2].tls);

        assert_eq!(endpoints[3].addr, "vps.example.com:7777");
        assert!(endpoints[3].tls);
    }

    #[test]
    fn test_parse_addrs_empty() {
        let addrs: Vec<String> = vec![];
        let endpoints = parse_addrs(addrs);
        assert!(endpoints.is_empty());
    }

    #[test]
    fn test_parse_addr_some() {
        let ep = parse_addr(Some("127.0.0.1:8080".to_string()));
        assert!(ep.is_some());
        let ep = ep.unwrap();
        assert_eq!(ep.addr, "127.0.0.1:8080");
        assert!(!ep.tls);
    }

    #[test]
    fn test_parse_addr_some_with_tls() {
        let ep = parse_addr(Some("+127.0.0.1:8080".to_string()));
        assert!(ep.is_some());
        let ep = ep.unwrap();
        assert_eq!(ep.addr, "127.0.0.1:8080");
        assert!(ep.tls);
    }

    #[test]
    fn test_parse_addr_none() {
        let ep = parse_addr(None);
        assert!(ep.is_none());
    }

    #[test]
    fn test_parse_addrs_ipv6() {
        let addrs = vec!["[::1]:8080".to_string()];
        let endpoints = parse_addrs(addrs);

        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].addr, "[::1]:8080");
        assert!(!endpoints[0].tls);
    }

    #[test]
    fn test_parse_addrs_ipv6_with_tls() {
        let addrs = vec!["+[::1]:8080".to_string()];
        let endpoints = parse_addrs(addrs);

        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].addr, "[::1]:8080");
        assert!(endpoints[0].tls);
    }
}
