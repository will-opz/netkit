# NetKit

Zero-external-dependency Go network diagnostics CLI. V1 provides multi-source IP geolocation and WHOIS registration lookup with fault isolation.

## Install and update

Requires Go 1.23+ and Make. Clone once, then run `make` whenever you want to update the checkout and rebuild the binary:

```sh
git clone https://github.com/will-opz/netkit.git
cd netkit
make                  # git pull --ff-only + go build -o netkit ./cmd/netkit
make deploy           # install ~/.local/bin/netkit
~/.local/bin/netkit
```

Use `make deploy` to build and install to `~/.local/bin/netkit` (creates the directory if needed, no sudo, does not pull). Use `make build` to compile without pulling, `make check` for tests and vet, `make fmt` to format sources, and `make help` for the list. If `~/.local/bin` is on your `PATH`, invoke `netkit` directly; otherwise use `~/.local/bin/netkit`. Override the install directory with `make deploy INSTALL_DIR=/custom/path`. Updates are fast-forward only; `make` refuses to pull when tracked files contain uncommitted changes. The generated `./netkit` binary stays ignored by Git.



## Usage

```sh
./netkit --help                              # 总帮助：子命令、选项、示例
./netkit --output json                      # 本机网络概览 JSON
./netkit                                      # 等同于 netkit ip，显示本机内外网、网关
./netkit ip                                   # 本机接口、内网地址、默认网关与公网信息
./netkit ip 192.168.1.1                       # 本地分类，不请求公网 GeoIP / WHOIS
./netkit ip 8.8.8.8                           # 默认中文单行汇总
./netkit ip --output json 8.8.8.8            # 推荐的 JSON 输出方式
./netkit ip --output text 8.8.8.8            # 明确指定文本输出
./netkit ip -lang en 8.8.8.8                  # English output
./netkit ip 8.8.8.8 1.1.1.1                   # one line per IP
./netkit ip -all 8.8.8.8                      # full WHOIS and per-provider JSON
./netkit ip -whois 8.8.8.8                    # TCP 43 only
./netkit ip -rdap 8.8.8.8                     # HTTPS RDAP (IANA bootstrap)
./netkit ip -rdns 8.8.8.8                     # reverse DNS PTR
./netkit ip -bgp 8.8.8.8                      # RIPE RIS announced prefix/ASN
./netkit ip -rdap -rdns -bgp 8.8.8.8         # all three optional enrichments
./netkit ip -json 8.8.8.8                     # 旧版 JSON 参数，仍然兼容
./netkit ip -timeout 8s 2001:4860:4860::8888
./netkit ip -cidr 192.168.31.158/24           # IPv4 网段、掩码、广播和地址数量
./netkit ip -cidr 2001:db8::/126 -contains 2001:db8::3 # IPv6 网段包含判断
printf '8.8.8.8\n1.1.1.1\n' | ./netkit ip -stdin  # 标准输入批量查询
cat ips.txt | ./netkit ip -stdin --output json # 按输入顺序输出 JSON 数组
cat ips.txt | ./netkit ip -stdin -workers 2 -interval 2s # 请求节流
```

`--output` accepts `text` (default) or `json`; the original `-json` flag is kept as an alias. `netkit --output json` works without an explicit `ip` subcommand. JSON keys remain English regardless of `-lang`. An unsupported format returns a nonzero exit status.\n\nNote: Go's standard `flag` parser expects options before IP arguments (e.g. `netkit ip -all 1.1.1.1`).

### IP 类型和本机网络检查

指定内网、回环、链路本地、CGNAT、文档保留等非公网地址时，只做本地地址分类并跳过 GeoIP/WHOIS。

直接执行 `netkit`（等同于 `netkit ip`）显示本机主机名、活动接口 IPv4/IPv6 地址与掩码、首选出口地址、默认 IPv4/IPv6 网关，以及通过多个 HTTPS 服务发现的公网 IP 和综合查询结果。公网查询失败不会阻止本地信息显示。

网关检测：Linux 读取 `/proc/net/route` 与 `/proc/net/ipv6_route`；macOS 使用系统内置的 `route -n get` 命令（无需第三方软件）；其他平台标记为不可用，不猜测路由器地址。VPN/多路由环境中仅展示操作系统路由表确定的默认路由；无默认路由时显示不可用。

默认终端输出按 **主机 / 主要接口 / 默认网关 / 公网信息** 分组。只显示出口网卡和默认路由对应网卡；macOS 的 utun、bridge、awdl 等额外接口折叠为数量提示。使用 `netkit ip -all` 或 `netkit ip -json` 查看全部接口和完整查询数据，不会丢失原始信息。终端默认不使用 ANSI 颜色，方便重定向和日志采集。

不带地址时 `-json` 输出含 `interfaces`、`gateways`、`public_ip`、`public` 的对象；指定 IP 时保持此前的结果数组结构。`-all` 展开公网信息的各数据源详情。

### Compact output

By default, each IP produces **exactly one line**, suitable for terminals and batch scripts. Example of the format (illustrative, not live results):

```text
8.8.8.8 | 美国 | AS15169 | Google LLC | 机房: 是 | 数据源: 4/4 | WHOIS: OK
```

Default output language is **Simplified Chinese** (`-lang zh`). Use `-lang en` for English. `数据源: 4/4` counts successful HTTP providers; it **does not mean all four agree**. Region and city are combined as per-provider location pairs, then deduplicated and shown together (e.g. `地点候选: 东京/新宿、千叶县/千叶`). Each pair comes from the same source, and candidates are ordered by provider agreement count (stable ties). The JSON `summary.locations` array includes each candidate and the providers reporting it. Distinct country/ASN results still trigger `GeoIP 差异`. `机房: 未知` means no provider supplied a detection; it is not equivalent to `否`. Unknown country codes are left unchanged, and provider-supplied city and region names are not automatically translated.

`-all` preserves the detailed, multi-line original results for troubleshooting (field labels localized, original provider JSON untouched). `-json` returns structured reports with **stable English keys and original country codes regardless of language**, including field-level agreements, alternatives and WHOIS. This keeps JSON consumers backward compatible.

## Optional IP enrichments (V1.1)

GeoIP location candidates now merge a small, curated set of equivalent English/Chinese names (for example California/加利福尼亚州, Mountain View/山景城, Virginia/弗吉尼亚州, Ashburn/阿什本). The terminal shows localized labels with `-lang zh|en`; unknown names remain unchanged. Candidate grouping retains each API's original values in `sources[].data` and lists contributing provider names under `summary.locations[].sources`. This is normalization, not independent verification of physical location.\n\nRDAP now extracts registrant organizations and abuse contact emails from nested `entities` and `vcardArray` structures. The text view omits unknown countries instead of displaying a blank separator; `--output json` includes optional `rdap.organization`, `rdap.abuse_emails`, and role-tagged `rdap.contacts`. Missing country is not inferred from an address string.\n\nThe default `netkit ip <IP>` remains unchanged. Optional flags add independent, timeout-bounded information (shown below the summary, or structured under `rdap`, `ptr`, and `bgp` when `--output json` is used):

- `-rdap`: download the IANA IPv4/IPv6 HTTPS bootstrap registry, longest-prefix match the IP, and query the selected registration server for the IP network. RDAP is authoritative registration data, **not a location claim**.
- `-rdns`: perform a standard-library PTR reverse lookup; no PTR result is a normal outcome.
- `-bgp`: call RIPEstat RIS `network-info` to return an observed announced prefix and one or more origin ASNs. Data comes from RIS routing observations and may lag real-time changes.
- These flags only run for public IPs and are skipped for private/reserved IPs. Errors are isolated by subsystem and do not discard GeoIP/WHOIS results.

For flag parsing with the Go standard library, put options before positional IPs: `netkit ip -bgp 8.8.8.8`, not `netkit ip 8.8.8.8 -bgp`.

Reference documentation: [RFC 9224](https://www.rfc-editor.org/rfc/rfc9224), [RIPEstat network-info API](https://stat.ripe.net/docs/data-api/api-endpoints/network-info.html).

## CIDR and stdin batch (V1.2)

- **Offline CIDR calculator**: `netkit ip -cidr 192.168.31.158/24` prints the normalized network, version, mask (IPv4), first and last IP, IPv4 broadcast, usable-host count and total address count. `-contains <IP>` checks prefix membership. IPv6 uses arbitrary-precision counts and has no broadcast field. CIDR mode never contacts external APIs.
- **Batch input**: `netkit ip -stdin` reads one IPv4 or IPv6 address per line. Blank lines and `#` comments are ignored. Duplicate addresses are removed; results retain first-seen order. Maximum 1,000 entries per invocation.
- **Throttling**: `-workers 2` is the default bounded concurrency (range 1–4) and `-interval 1.5s` spaces out the start of separate lookups in stdin mode to reduce API rate-limit errors. Multiple independent processes are not coordinated; respect each data provider's limits. You can increase the interval or run `-whois` when HTTP APIs aren't required.
- **Output**: `--output json` returns a single object for CIDR, or an array of IP results for stdin. Standard `netkit` without arguments continues to show the local network overview. In Go's standard flag parser, put options *before* the positional IPs.

## Data sources

- ip-api.com (free API uses **unencrypted HTTP**)
- ipwho.is
- ipinfo.io
- api.ip.sb
- IANA / RIR WHOIS over native TCP/43, with bounded recursive referrals
- Public IP discovery fallback: api.ipify.org, ifconfig.me/ip, icanhazip.com

GeoIP endpoints are queried concurrently alongside WHOIS, with independent timeouts and error reporting. WHOIS registration country is not a geolocation. Multiple agreeing API responses are not necessarily independent data sets; provider limits and terms still apply.

## Development

```sh
go test ./...
go vet ./...
go build ./cmd/netkit
```

## Roadmap

- V1.2: CIDR calculation and bounded stdin batch queries (available). Next: field selection, caching and provider health checks.
- V2: RDAP, ASN and DNS.
- V3: TCP/TLS/HTTP diagnostics and traceroute.

Design inspirations for future versions: [ipinfo/cli](https://github.com/ipinfo/cli) (CLI and batch UX), [zu1k/nali](https://github.com/zu1k/nali) (offline sources and multi-result presentation), [openrdap/rdap](https://github.com/openrdap/rdap) (registration data and bootstrap).
