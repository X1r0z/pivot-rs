use rand::{distributions::Alphanumeric, thread_rng, Rng};

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
