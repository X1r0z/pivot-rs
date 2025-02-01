use rand::{distributions::Alphanumeric, thread_rng, Rng};

pub fn generate_random_string(length: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

pub fn parse_addrs(addrs: Vec<String>) -> Vec<(String, bool)> {
    let parsed_opts: Vec<bool> = addrs.iter().map(|addr| addr.starts_with('+')).collect();
    let parsed_addrs: Vec<String> = addrs
        .iter()
        .map(|addr| addr.replace("+", ""))
        .map(|addr| {
            if addr.contains(":") {
                addr
            } else {
                format!("0.0.0.0:{}", addr)
            }
        })
        .collect();

    parsed_addrs.into_iter().zip(parsed_opts).collect()
}

pub fn parse_addr(addr: Option<String>) -> Option<(String, bool)> {
    match addr {
        Some(addr) => parse_addrs(vec![addr]).pop(),
        None => None,
    }
}
