# AGENTS.md

## Build & Test Commands
- Build: `cargo build` (release: `cargo build --release`)
- Check: `cargo check`
- Lint: `cargo clippy`
- Format: `cargo fmt`
- Test all: `cargo test`
- Test single: `cargo test <test_name>` (e.g., `cargo test test_tcp_forward_local_to_local`)
- Run: `cargo run -- <fwd|proxy|reuse> [options]`

## Architecture
Rust async networking tool using Tokio runtime. Three modes: port forwarding (`fwd`), SOCKS5 proxy (`proxy`), and port reuse (`reuse`). TLS encryption via rustls with self-signed certs. TCP multiplexing via async_smux.

**Key modules:** `lib.rs` (CLI/entry), `forward.rs` (port forwarding), `proxy.rs` (SOCKS proxy), `socks.rs` (SOCKS5 protocol), `reuse.rs` (port reuse), `tcp.rs`/`udp.rs` (transport), `crypto.rs` (TLS), `util.rs` (helpers)

## Code Style
- Use `anyhow::Result` for error handling; propagate with `?`
- Async functions with Tokio; use `tokio::spawn` for concurrent tasks
- Logging via `tracing` crate (`info!`, `warn!`, `error!`)
- clap derive macros for CLI parsing
- Unix-specific code: `#[cfg(target_family = "unix")]`
- No comments unless complex logic requires explanation
