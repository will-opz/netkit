# NetKit Diagnostic Roadmap (OpsKitPro Comparative Review)

Reviewed: 2026-11-20. Sources: [OpsKitPro](https://github.com/will-opz/opskitpro) `docs/architecture.md`, `docs/roadmap.md`, `src/lib/diagnostic-route.ts`, `src/lib/diagnostic-model.ts`, `src/lib/http-assessment.ts`, `src/app/api/dns/route.ts`, `src/app/api/network/*`, `src/lib/cloudflare-trace.ts`, `src/app/[lang]/tools/dns-lookup/hooks/useSecurityAudit.ts`. Compare against NetKit `cmd/netkit/`.

## Product boundary

NetKit is a local, zero-third-party-Go-dependency SRE network diagnostic CLI. OpsKitPro is a browser/server-based suite with remote observation points. Borrow *diagnostic reasoning and evidence contracts*, not its full web tool catalog. A successful observation from AWS Lightsail or a Cloudflare Edge probe is **not** a local-client measurement. Do not copy environment-specific credentials or deployment logic.

Maintain `netkit <IP>` / `netkit <domain>` quick summaries; intensive probes stay under explicit subcommands. JSON outputs are structured and bilingual text is concise. Every claim should identify its observation point and what was *actually* measured; avoid arbitrary health scores, and never infer "no CDN" from missing signatures.

## Backlog and phased implementation

| Priority | Candidate | OpsKitPro reference | NetKit gap | Acceptance |
| --- | --- | --- | --- | --- |
| P0.1 | `netkit tls HOST` | `diagnostic-route.ts` TLS probe | No standalone certificate/chain validation | Show handshake, chain/hostname verification, issuer, SAN, validity window, TLS version, cipher, ALPN, bounded timeout, JSON, offline tests |
| P0.2 | `netkit http HOST` | `tools/http.ts` and redirect tracing | Domain shows final URL/status but not each hop | Show exact redirect chain and failures, loop/limit checks, per-hop timing; 403/429 not "site down"; safe redirect handling |
| P0.3 | `netkit tcp HOST PORT` | Network Doctor reachability | No dedicated local TCP probe | DNS/TCP duration, connection outcome vs HTTP status, IPv4/IPv6, error/timeout and JSON |
| P1.1 | Deeper `netkit dns` | DNS API and Security Audit | Basic records, system/Cloudflare/Google compare | SOA/SRV/CAA/TTL/RCODE, DNSSEC evidence boundaries, explain differing answers |
| P1.2 | CDN evidence | Website Check CDN classification | Limited CNAME/headers | Source-labeled evidence, no assertions without signatures, handle conflicts, flattened CNAME |
| P1.3 | HTTP security headers | `buildSecurityHeadersSummary` | No independent check | HSTS/CSP/X-Content-Type-Options etc.; show presence and conditional advice, not a universal score |
| P2 | `netkit cf trace` | `cloudflare-trace.ts` | No CF trace CLI | Validate response size/content; label exact observation path and optional target vs self |
| P2 | Mail domain policy | DNS SPF/DMARC/CAA audit | No policy analysis | Separate `dns security` mode, no false failure for non-mail domain |
| P3 | WebSocket / advanced remote probes | WebSocket workbench, multi-observation model | No interactive workbench | Only if demand supports CLI usage and dependency/security cost |

Not in scope by default: password management, JSON/YAML/SQL formatting, QR, browser UI, AI general chat, remote Cloudflare Edge authentication, or collecting private OpsKitPro control-plane data.

## Evidence-first output conventions

1. Observation: what was directly seen (resolver/IP, TCP handshake, TLS peer cert, HTTP status, time, location of probe).
2. Assessment: deterministic classification (success/restricted/failure/unknown). For HTTP, 401/403/429 represent access restrictions, 5xx origin/proxy HTTP failures; neither alone proves global reachability.
3. Inference: evidence-backed likely root cause and confidence, explicitly optional.
4. Guidance: actionable, contextual next diagnostic step; never invent facts.
5. Unknown/partial failures remain visible; no generic 0–100 health score.

## Domain correctness and safety

- Current domain apex detection uses a small manually maintained suffix list. Evaluate a Public Suffix List strategy before broadening assumptions; explicit subdomains must remain single-host checks.
- Keep bounded timeouts, independent provider failure handling and no infinite redirects.
- A CLI may test localhost/private IPs intentionally; a remote public API must apply stricter SSRF rules. Do not blindly copy server-only input restrictions to local diagnostics.
- TLS verification and certificate collection must be separate outcomes; a failed handshake and a chain validation failure are not equivalent.

## Release policy

Development changes and passing CI do **not** update `will-opz/homebrew-tap`. Only after an explicitly tagged official version **and** verified GitHub Release should the Homebrew formula be changed. Do not silently bump its source snapshot per commit.

## Delivery checklist per feature

- [ ] Tests for successful, invalid and timeout outcomes without relying on external endpoints
- [ ] Bilingual terminal guidance, `--output json`, clear exit semantics
- [ ] `go test ./...`, `go vet ./...`, `go build ./cmd/netkit` via GitHub Actions
- [ ] README and CLI help consistent
- [ ] No Homebrew Tap mutation before an official tagged Release

## Progress

- [x] Review OpsKitPro architecture, diagnostics and DNS/security implementations.
- [ ] P0.1 TLS command (start here).
- [ ] P0.2 HTTP redirect chain.
- [ ] P0.3 TCP reachability.
