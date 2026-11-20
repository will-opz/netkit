# NetKit

Zero-external-dependency Go network diagnostics CLI. V1 provides multi-source IP geolocation and WHOIS registration lookup with fault isolation.

## Build

Go 1.23+:

```sh
git clone https://github.com/will-opz/netkit.git
cd netkit
go build -o netkit ./cmd/netkit
```

## Usage

```sh
./netkit --help
./netkit ip                                   # discover public IP
./netkit ip 8.8.8.8                           # one-line summary
./netkit ip 8.8.8.8 1.1.1.1                   # one line per IP
./netkit ip -all 8.8.8.8                      # full WHOIS and per-provider JSON
./netkit ip -whois 8.8.8.8                    # TCP 43 only
./netkit ip -json 8.8.8.8                     # machine-readable output
./netkit ip -timeout 8s 2001:4860:4860::8888
```

Note: Go's standard `flag` parser expects options before IP arguments (e.g. `netkit ip -all 1.1.1.1`).

### Compact output

By default, each IP produces **exactly one line**, suitable for terminals and batch scripts. Example of the format (illustrative, not live results):

```text
8.8.8.8 | 美国 | AS15169 | Google LLC | Hosting: Yes | Sources: 4/4 | WHOIS: OK
```

`Sources: 4/4` counts successful HTTP providers; it **does not mean all four agree**. If reported country/region/city/ASN differs, a difference indicator is appended. `Hosting: Unknown` means no provider supplied a detection; it is not equivalent to `No`.

`-all` preserves the detailed, multi-line original results for troubleshooting. `-json` returns structured reports, including field-level agreements, alternatives and WHOIS.

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

- V1.1: stdin/batch input, field selection, bounded concurrent batch queries, caching and provider health checks.
- V2: RDAP, ASN and DNS.
- V3: TCP/TLS/HTTP diagnostics and traceroute.

Design inspirations for future versions: [ipinfo/cli](https://github.com/ipinfo/cli) (CLI and batch UX), [zu1k/nali](https://github.com/zu1k/nali) (offline sources and multi-result presentation), [openrdap/rdap](https://github.com/openrdap/rdap) (registration data and bootstrap).
