# NetKit

Zero-external-dependency Go network diagnostics CLI. V1 provides multi-source IP geolocation and WHOIS registration lookup with fault isolation.

## Install and update

Requires Go 1.23+ and Make. Clone once, then run `make` whenever you want to update the checkout and rebuild the binary:

```sh
git clone https://github.com/will-opz/netkit.git
cd netkit
make                  # git pull --ff-only + go build -o netkit ./cmd/netkit
make deploy           # Homebrew Tap install/upgrade (published version)
netkit
```

Use `make deploy` to install or upgrade the **published** `will-opz/tap/netkit` formula through Homebrew. This requires Homebrew and does not deploy or compile your uncommitted local source. Use `make build` for a local development build; `make check` for tests and vet, `make fmt` to format sources, and `make help` for the list. Run `brew update && brew upgrade will-opz/tap/netkit` directly if preferred. Updates are fast-forward only; `make` refuses to pull when tracked files contain uncommitted changes. The generated `./netkit` binary stays ignored by Git.



## Usage

```sh
./netkit --help                              # 总帮助：子命令、选项、示例
./netkit --output json                      # 本机网络概览 JSON
./netkit 192.168.1.1                         # 自动识别 IP，等同 netkit ip 192.168.1.1
./netkit www.baidu.com                       # 自动识别域名，等同 netkit domain www.baidu.com
./netkit dns                                 # 本机 DNS 配置
./netkit dns --output json                   # 本机 DNS 配置 JSON
./netkit dns list                            # 常用公共 DNS 清单
./netkit dns compare baidu.com               # 比较本机/Cloudflare/Google DNS 结果
./netkit dns compare --output json baidu.com # DNS 对比 JSON
./netkit tls example.com                     # TLS 握手、证书信任链、颁发者与到期时间
./netkit tls -port 8443 --output json example.com # 自定义端口和 JSON
./netkit http example.com                    # HTTP 状态和跳转链
./netkit http --output json https://example.com/path # HTTP 逐跳 JSON（含 DNS/TCP/TLS/TTFB 阶段）
./netkit tcp example.com 443                 # DNS + TCP 连接诊断
./netkit tcp -all-ips example.com 443        # 逐个检测所有 A/AAAA 地址
./netkit tcp --output json 127.0.0.1 5432    # 本地服务 TCP JSON
./netkit dns list --output json              # 公共 DNS 清单 JSON
./netkit domain example.com                  # 主域名和 www 的 CDN/网站可用性 + 注册信息
./netkit domain records example.com          # 详细 A/AAAA/MX/NS/TXT/CNAME 记录
./netkit domain records --output json example.com  # DNS 记录 JSON
./netkit domain -no-rdap example.com         # 网站/CDN 检查，跳过 RDAP
./netkit domain --output json example.com   # 域名查询 JSON
./netkit                                      # 等同于 netkit ip，显示本机内外网、网关
./netkit ip                                   # 本机接口、内网地址、默认网关与公网信息
./netkit ip 192.168.1.1                       # 本地分类，不请求公网 GeoIP / WHOIS
./netkit ip 8.8.8.8                           # 默认中文单行汇总，标识已知公共 DNS
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

## HTTP phase timing and TCP all-address checks (O1/O2)

HTTP redirect hops now contain optional `phases` fields: `dns_ms`, `connect_ms`, `tls_ms`, `ttfb_ms` and `reused_connection`. Collected with Go's `net/http/httptrace` as direct observations. Unobserved phases are omitted rather than shown as zero (e.g. connection reuse, literal IP, custom transports, proxies). Time values are request-local and can overlap or reflect a proxy rather than the origin. The existing per-hop `duration_ms` remains unchanged. TTFB here means elapsed after the request is written until the first response byte, **not** the total time from initial DNS resolution.

TCP's default remains fast: stop at the first successful IP. `netkit tcp -all-ips example.com 443` checks every unique resolved IPv4/IPv6 address **sequentially** within the same overall `-timeout` budget, returning `connected` when all tested addresses succeed, `partial_failure` when some connect and some fail, `connect_error` when none connect, or `timeout` if the budget expires. It includes `all_ips`, `success_count`, `failure_count`, and per-address attempts in JSON. A partial failure returns a nonzero process status; no single good backend masks a bad one. DNS order may vary by resolver.

## TCP reachability diagnostics (P0.3)

`netkit tcp example.com 443` performs a local DNS lookup (or skips DNS for a literal IPv4/IPv6 address) then attempts TCP connections to resolved addresses, stopping on first success. Reports DNS latency, resolved IP addresses, address family, per-attempt TCP latency, connected IP and error details. If one address fails, it tries the next, subject to a **single overall timeout** (`-timeout 5s`). Works with loopback/private hosts for local operations. This does **not** verify TLS certificates, send HTTP requests, or prove the application is healthy.

Failure categories: `dns_error`, `connect_error`, `timeout`; success: `connected`. Text supports `-lang zh|en`, `--output json` provides structured details. Exit status is nonzero on failure. The observation is made **from the machine executing NetKit**, so it may differ under VPN, container or firewall routing.

## HTTP redirect diagnostics (P0.2)

`netkit http example.com` makes a local HTTPS request and traces up to five redirects (configurable with `-max-redirects 0..20`). Explicit `http://` or `https://` URLs and paths are preserved. Each HTTP hop records its status, latency and `Location` header; the final URL, redirect count and HTTPS-to-HTTP downgrades are reported. Loop, redirect limit, unsupported redirect scheme and connection failures are distinct. HTTP 401/403/407/429 classify as restricted, 4xx/5xx as HTTP errors. Status success means a 2xx final response; the command returns a nonzero exit code for other outcomes. It intentionally does not automatically inspect `www` or silently try HTTP after an HTTPS error. Use `--output json`, `-lang en`, `-timeout 5s`, `-max-redirects 5`. This is a **local probe** and intentionally permits private/local endpoints; do not expose it as an unrestricted remote API.

## TLS certificate diagnostics (P0.1)

`netkit tls HOST` runs a local TCP/TLS handshake and shows the negotiated protocol, cipher, ALPN, certificate subject/issuer, validity dates and number of days remaining. It then **independently verifies** the peer's certificate against the machine's system trust store, intermediate chain, server-auth usage and requested host/IP. An expired, untrusted or hostname-mismatched certificate reports a verification error even if the handshake succeeded.

The probe intentionally collects an untrusted certificate during the diagnostic-only handshake (with verification performed explicitly afterward); it sends no HTTP/application payload. Certificate failure or connection failure returns a nonzero exit status. Use `-port`, `-timeout`, `-lang zh|en`, and `--output json`. If running inside a VPN or container, the observation reflects **that machine's** routing and trust store.

See [diagnostic implementation roadmap](docs/diagnostics-roadmap.md) for planned TCP, HTTP redirect and evidence-first work. Development commits do **not** automatically update the Homebrew Tap; only a validated official tagged Release triggers a formula update.

## Known public DNS detection

`netkit 8.8.8.8` and `netkit ip 1.1.1.1` now perform an **offline exact-address lookup** against the same catalog as `netkit dns list`, before querying GeoIP or WHOIS. Positive matches are labeled `公共 DNS: Google Public DNS` / `Public DNS: Cloudflare`, with `known_dns` metadata in JSON (`provider`, `role`, `match`, `doh`). The flag `-all` also shows the matched provider.

Only the specific public resolver addresses in the catalog are recognized: the program does not infer DNS status from PTR records, ASN, hosting, or neighboring addresses. A missing match means **not in the built-in list**, not “not a DNS server.” This is static catalog identification, not an active DNS availability or service verification. Both IPv4 and IPv6 are supported; GeoIP/WHOIS behavior remains unchanged.

## Smart command routing and DNS / domain (V1)

- **Automatic routing:** `netkit <IPv4|IPv6>` is equivalent to `netkit ip <IP>`, while `netkit example.com` is equivalent to `netkit domain example.com`. Explicit `ip`, `dns`, `domain` subcommands take priority. Bare `netkit` still shows the local network overview. Domain auto-detection accepts ASCII/Punycode hostnames; URLs and Unicode IDNs are not accepted directly.
- **System DNS:** `netkit dns` shows resolver addresses and metadata. On macOS it reads `scutil --dns` (including supplemental and scoped resolver entries), with a fallback to `/etc/resolv.conf`. On Linux it reads `/etc/resolv.conf`. Displayed settings are configuration evidence, not proof of the actual server used by every app or encrypted DNS client.
- **Resolver comparison:** `netkit dns compare baidu.com` compares A/AAAA and canonical CNAME results from system DNS, Cloudflare (`1.1.1.1:53`), and Google (`8.8.8.8:53`) concurrently. It uses Go standard-library resolvers with bounded timeouts, supports `--output json` and `-timeout 8s`, and reports each resolver error independently. Differences are diagnostic signals only: CDN/GeoDNS and ECS/location routing can legitimately vary answers. Network policy/VPN may block direct DNS port 53.
- **Release policy:** day-to-day commits on `main` do **not** update `will-opz/homebrew-tap`. Update the Homebrew formula only after an official version tag and GitHub Release have been created and validated; a pending feature does not bump the Tap.
- **Public DNS directory:** `netkit dns list` prints fixed reference addresses for Cloudflare, Google, Quad9 and AdGuard (IPv4/IPv6 and DoH URL). This is not a live availability, speed or security assessment.
- **Default domain overview:** `netkit baidu.com` checks the apex and `www.baidu.com` only, reporting HTTPS reachability (with HTTP fallback when HTTPS fails), status code, latency, CDN indicators and RDAP registration details. `netkit www.baidu.com` or any explicitly supplied subdomain checks only that hostname. Apex inference uses a conservative, small common-suffix list, not a full Public Suffix List: for unusual public suffixes, specify each desired hostname explicitly.
- **CDN identification:** based on a recognized CNAME suffix (stronger evidence) or combinations of characteristic HTTP headers (labeled a hint, not proof). Conflicting evidence is labeled as such; otherwise unknown remains unknown. CDN services can flatten CNAMEs or suppress headers, so false negatives are possible. No claim of DNSSEC or end-to-end browser health is made.
- **Website health:** HTTP 2xx/3xx = successful HTTP response, 401/403 = access restricted, 404/5xx = HTTP error, network/TLS failure = unavailable unless HTTP fallback succeeds. Redirect destination, response code and errors are included in JSON. Each website check has bounded timeouts. A redirect to an unrelated host is rejected by the current probe policy.
- **DNS record details:** `netkit domain records example.com` explicitly queries A, AAAA, CNAME, MX, NS and TXT through the system resolver; absent optional records are not treated as errors. Use `--output json` for structured data. These records are not fetched for the default website overview.
- **RDAP registration:** default overview separately queries IANA domain bootstrap and registry RDAP for registrar, creation, expiration, update and status; HTTP 404 on a subdomain triggers a parent lookup. Use `-no-rdap` to skip registration. RDAP errors do not discard website checks. Registry expiry may differ from registrar billing/renewal details. Absent optional records (such as MX/TXT on a web hostname) are treated as empty; genuine DNS failures are reported independently under JSON `errors`. Output supports `--output json`, `-lang zh|en`. Options must precede the domain due to Go standard flag parsing.
- Both modules use Go's standard library only. Native custom DNS-server selection, DNSSEC validation and detailed authoritative trace are future enhancements.

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
