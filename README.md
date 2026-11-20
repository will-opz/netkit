# NetKit

A zero-dependency Go network diagnostics toolkit. **V1: `ip-lookup`** aggregates GeoIP information and native WHOIS registration data.

## Build

Go 1.20+:

```sh
go build -o ip-lookup ./cmd/ip-lookup
```

## Usage

```sh
./ip-lookup                            # discover and look up public IP
./ip-lookup 1.1.1.1 8.8.8.8            # multiple IPv4 / IPv6 targets
./ip-lookup -all 1.1.1.1               # per-source response and WHOIS text
./ip-lookup -whois 1.1.1.1             # native TCP/43 only
./ip-lookup -json 1.1.1.1              # machine-readable output
./ip-lookup -timeout 8s 1.1.1.1       # per-source timeout
```

## Data sources

- ip-api.com (`http://` free endpoint; **unencrypted**)
- ipwho.is
- ipinfo.io
- api.ip.sb
- IANA → RIR WHOIS over TCP port 43 (no system `whois` command)
- Public IP discovery: api.ipify.org, ifconfig.me/ip, icanhazip.com

HTTP sources and WHOIS run concurrently. A failing API does not suppress successful sources. Country/region/city/ASN/ISP/organization are compared per field; `agreements` records contributing providers and disagreements. Agreement across API responses **does not prove independent databases or accuracy**. GeoIP locations are estimates; WHOIS country denotes registration and may not be physical location. Missing proxy/hosting detections remain unknown. Providers have their own terms and rate limits.

WHOIS traversal is capped at four registry hops and a bounded total duration, and referrals are restricted to known RIR hosts.

## Roadmap

- V1.1: stdin/batch mode, request concurrency limits, tests/CI, caching and rate-limit awareness.
- V2: RDAP, ASN and DNS resolver comparisons.
- V3: TCP/TLS, HTTP, traceroute and network diagnostics.

## Development

```sh
go test ./...
go vet ./...
```
