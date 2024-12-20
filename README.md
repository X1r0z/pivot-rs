# Rsproxy

Rsproxy is a lightweight port-forwarding and socks proxy tool written in Rust 🦀

## Build

The project is under development, so you need to build yourself.

```bash
git clone https://github.com/X1r0z/rsproxy
cd rsproxy
cargo build --release
```

## Usage

### Port Forwarding

Listen on `0.0.0.0:8888` and `0.0.0.0:9999`, forward traffic between them.

*specify `127.0.0.1:PORT` to listen on local address*

```bash
./rsproxy fwd -l 8888 -l 9999
```

Listen on `0.0.0.0:8888`, forward traffic to a remote address.

```bash
./rsproxy fwd -l 8888 -r 10.0.0.1:9999
```

Connect `10.0.0.1:8888` and `10.0.0.2:9999`, forward traffic between them.

```bash
./rsproxy fwd -r 10.0.0.1:8888 -r 10.0.0.1:9999
```

A basic example of accessing an intranet address through port forwarding.

```bash
# on attacker's machine
./rsproxy fwd -l 8888 -l 9999

# on victim's machine
./rsproxy fwd -r 10.0.0.1:3389 -r vps:8888

# now attacker can access 10.0.0.1:3389 through vps:9999
```

A complex example, multi-layer proxy in the intranet.

```bash
# on machine A (10.0.0.1, 172.16.0.1)
./rsproxy fwd -r 10.0.0.10:3389 -l 7777

# on machine B (172.16.0.2, 192.168.1.1)
./rsproxy fwd -r 172.16.0.1:7777 -r 192.168.1.2:8888

# on machine C (192.168.1.2, DMZ)
./rsproxy fwd -l 8888 -r vps:9999

# on attacker's machine
./rsproxy fwd -l 9999 -l 33890

# now attacker can access 10.0.0.10:3389 through vps:33890
```

Note that the command on machine B need to be executed last. Because this mode will check the connectivity between the two remote addresses.

### Socks Proxy

Rsproxy supports socks5 protocol (no authentication)

Forward socks proxy.

```bash
./rsproxy socks -l 1080
```

Reverse socks proxy.

```bash
# on attacker's machine
./rsproxy socks -l 7777 -l 8888

# on victim's machine
./rsproxy socks -r vps:7777

# now attacker can use socks proxy on vps:8888
```

## Reference

[https://github.com/EddieIvan01/iox](https://github.com/EddieIvan01/iox)
