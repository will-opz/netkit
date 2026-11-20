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

- Domain apex detection uses a pinned, embedded Mozilla Public Suffix List (ICANN + PRIVATE) under MPL-2.0, including wildcard/exception and Unicode/Punycode rules; review upstream snapshots intentionally before updating. Explicit subdomains remain single-host checks.
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
- [x] P0.1 TLS command (first implementation: handshake, trust, dates, ALPN, JSON and local tests; continue refining based on field feedback).
- [x] P0.2 HTTP redirect chain (standalone command, bounded hops, per-hop status/location/duration, error categories and offline tests).
- [x] P0.3 TCP reachability (local DNS/TCP probes, IPv4/IPv6, resolved-IP fallback, bounded timeout, JSON and offline tests).


## Peer-tool research and optimization plan (2026-11-20)

Peer tools reviewed for product direction: `dig`, `doggo`, `dnsx` (DNS and bulk); `curl`, `httpstat`, `HTTPie` (HTTP stages and UX); `openssl`, `testssl.sh`, `step` (TLS); `mtr`, `Trippy`, `gping` (network path). These are *reference capabilities*, not promises to implement their entire feature sets. NetKit's distinguishing proposition remains **small local CLI, objective evidence, cross-layer explanations and structured automation output**.

### Next iteration: strengthen implemented commands before adding more

| Order | Work | Current NetKit baseline | Concrete acceptance criteria |
| --- | --- | --- | --- |
| O1 / highest (implemented) | HTTP per-phase timing via Go `net/http/httptrace` | Each redirect hop previously had only total elapsed time | Report DNS, connect, TLS, TTFB and total per hop when observable; indicate connection reuse, proxies and unavailable stages instead of inventing zeros; JSON and deterministic `httptest` coverage |
| O2 / highest (implemented) | TCP `-all-ips` opt-in | Default still stops after first successful resolved address | Default behavior unchanged; explicit flag checks each resolved A/AAAA address, bounded overall timeout, stable address order, per-IP status and failure evidence; IPv4/IPv6 local tests |
| O3 / highest (first milestone) | DNS diagnostics correctness | Compare focuses on A/AAAA; detailed records via system resolver | Expose raw RCODE (NOERROR/NXDOMAIN/SERVFAIL/REFUSED), TTL, SOA/CAA/SRV, CNAME comparison; distinguish transport errors from authoritative negative answers; do not label any difference as poisoning |
| O4 / high (implemented) | TLS verification classification | Handshake, peer cert and verification exist | Distinguish expired/not-yet-valid, hostname mismatch, untrusted chain, handshake failure and timeout; optionally show SAN, SNI/ALPN and chain; never claim valid because handshake succeeded |
| O5 / high (implemented) | Domain apex and CDN accuracy | Small hand-written suffix list; CNAME/header evidence | Evaluate an updatable Public Suffix List under zero-external-Go-dependency constraint; preserve explicit-subdomain semantics; keep unknown/conflicting CDN evidence and handle flattened CNAME conservatively |

### Reliability and developer-experience gates

1. **Stable output contracts:** version JSON schema where necessary, keep older command behavior and field meanings, support JSON Lines for bulk workflows only after defining compatibility and exit semantics.
2. **Consistent failure semantics:** document exit codes for usage errors, DNS failure, TCP failure, TLS validation failure and HTTP restriction/failure. Do not collapse network-unreachable and HTTP 403/429.
3. **Observation provenance:** record the observer (`local_machine`), target, timestamp, resolver and resolved address where applicable. A local probe is not global reachability evidence.
4. **Testing:** local deterministic tests for dual-stack fallback, slow/failed DNS, timeout/cancellation, HTTPS redirects/loop, proxies and TLS invalid certificates. Prefer strict CI build/vet/tests and smoke checks over live external sites.
5. **Release management:** align a future signed/immutable official version tag, GitHub Release assets, changelog and Homebrew Formula; do **not** update the Tap for ordinary commits.

### Longer-term feature choice

- Design `netkit diagnose TARGET` only after HTTP/TCP/TLS/DNS produce compatible evidence. It should summarize DNS → TCP → TLS → HTTP with a clear first failing layer, confidence and next checks, **not** an arbitrary 0–100 health score.
- Keep specialist capabilities optional: DNSSEC and authority tracing, Cloudflare trace, network traceroute, mail DNS policy and HTTP security headers; do not clone generic JSON/YAML/QR/password tools into NetKit.
- Prioritize diagnostics and comparison across resolvers, IPv4 versus IPv6, distinct A/AAAA backends and local versus remote observation points where explicitly available.
- Maintain NetKit as a network diagnostics CLI rather than a full security scanner, browser toolkit or remote monitoring service.

### P0 verification commands (current implementations)

From a local checkout, run `git pull --ff-only && make build && make check`, then use the locally built `./netkit` binary rather than assuming Homebrew has the latest unreleased changes.

```sh
# TLS certificate and handshake
./netkit tls baidu.com
./netkit tls -port 443 --output json www.baidu.com
./netkit tls -timeout 8s example.com

# HTTP redirect chain and access classification
./netkit http baidu.com
./netkit http --output json https://example.com/
./netkit http -max-redirects 10 -timeout 8s https://www.baidu.com/

# TCP connectivity (local observer, not TLS/HTTP status)
./netkit tcp baidu.com 443
./netkit tcp -timeout 3s --output json www.baidu.com 443
./netkit tcp 127.0.0.1 5432  # only succeeds if a local service listens there
```

Tests above may legitimately return nonzero (for example, blocked or closed ports, certificate validation errors or restricted HTTP access); inspect the detailed evidence rather than interpreting every failure as a NetKit bug.

### Iteration status (2026-11-20)

- [x] O1 HTTP phases: local `httptrace` callbacks for DNS/connect/TLS/TTFB, nullable durations in JSON, explicit connection reuse, loopback HTTP/TLS tests, preserve redirect-hop totals.
- [x] O2 TCP all-IPs: opt-in sequential per-address checks under overall timeout, explicit `partial_failure` and counters, retains default early success; offline local tests.
- [x] O3 phase 1: explicit `netkit dns query` through Cloudflare/Google DoH, raw RCODE, per-record TTL, SOA/CAA/SRV and Answer/Authority, negative-answer and transport-error isolation.
- [x] O3 phase 2: `dns compare -detail -type TYPE` adds public DoH RCODE, TTL and answer comparisons alongside the existing system DNS results; baseline comparison now includes CNAME; offline tests cover differing responses and failed providers.
- [ ] Future: native DNS wire queries for authoritative paths and explicit OS RCODE/TTL (do not conflate resolver APIs with wire-level observations).
- [x] O4 TLS error classification: stable `verification_code` and `connection_code` with typed x509/net error matching, validity/hostname/authority distinctions and offline tests.
- [x] O5 domain suffix / CDN evidence: embedded Mozilla Public Suffix List with ICANN/PRIVATE, wildcard/exception and Unicode-to-Punycode rule handling; redirect-safe CNAME versus final HTTP header evidence, unknown/conflict distinctions, deterministic offline tests.

No Homebrew Tap change: only an official tagged GitHub Release will trigger the next formula update.

### Pre-release quality pass (2026-11-20)

- [x] Fix `make deploy` Make/shell expansion: only consult and install/upgrade the published Homebrew formula, without changing the Tap.
- [x] Add macOS + Linux CI runtime test matrix, and compile-check Windows amd64 and ARM64 release targets on Linux.
- [x] Add JSON output contract tests for TLS, TCP, HTTP, DNS query and DNS compare; verify unobserved HTTP phases are omitted.
- [x] Differentiate HTTP transport timeout from other network errors.
- [x] Accept `localhost` for explicit local TLS/TCP checks.
- [x] Remove OS-specific `127.0.0.2` routing assumptions from TCP tests, injecting a deterministic dialer for simulated failures.
- [x] Prepare (without publishing) tagged GitHub Release workflow, five cross-platform archives, checksums, deterministic archive metadata, version/commit CLI and packaging dry-run.
- [ ] Before official release: maintainer selects the NetKit source license; validate release asset download and signatures/provenance as needed. Homebrew Tap update remains a separate step **only after** formal tagged GitHub Release verification.
- [ ] Consider future JSON schema versioning/JSONL and differentiated exit codes in an explicit compatibility release, not as a silent breaking change.

### Release workflow preparation (2026-11-20)

- [x] `netkit version` / `netkit --version` with optional build-time version/commit; JSON contract test.
- [x] Python standard-library deterministic packaging for Linux amd64/arm64, macOS amd64/arm64, Windows amd64; SHA256 manifest and archive content validator.
- [x] Release workflow: manual dispatch performs dry-run only; pushed strict `vMAJOR.MINOR.PATCH` tag publishes validated GitHub Release using its existing tag. No automatic Homebrew formula changes.
- [x] Ordinary GitHub CI dry-runs packaging and checksum validation, with macOS and Ubuntu test jobs.
- [ ] Confirm first-release license (top-level `LICENSE` currently absent); first official Tag, GitHub Release, binary download audit and Homebrew update require explicit separate action.

Release instructions: [docs/releasing.md](releasing.md). Changelog: [CHANGELOG.md](../CHANGELOG.md).


## Planned diagnose and optional AI integration (2026-11-20 design decision)

**Status: A0 and initial A1 transport implemented; model-quality and real-provider testing pending.** Preserve the zero-third-party-Go-dependency CLI and all existing deterministic commands. AI is **opt-in**, never a prerequisite for ordinary CLI commands or diagnostic measurements. Both local Qwen/Ollama/llama.cpp and commercial API/NewAPI use a **single OpenAI-compatible Chat Completions client**. Select provider through base URL, model and API-key environment variable, not provider-specific business logic. Compatibility varies: validate supported structured-output behavior per backend, with application-level schema and evidence-ID validation even when the model offers JSON mode.

### Delivery sequence

| Phase | Priority | Scope | Acceptance / boundaries |
| --- | --- | --- | --- |
| A0 / P0 | First | CLI ergonomics, deterministic `netkit diagnose TARGET`, unified `DiagnosticPlan` and `EvidenceBundle` | Existing `netkit <domain>` quick behavior stays unchanged; fixed default DNS → TCP → TLS → HTTP steps; stable observation point, target, timestamps, per-stage status/error, evidence IDs, overall timeout and JSON; determine the first confirmed failing layer without arbitrary health score; operate fully offline from AI |
| A1 / P1 | Second | Optional AI summary over completed `EvidenceBundle` | `netkit diagnose TARGET --ai` opt-in; single configurable API client for local Ollama/Qwen or HTTPS commercial API; response `ai_analysis` must cite valid evidence IDs, distinguish facts/hypotheses and recommend next checks; no original measurement may be changed; gracefully fall back on AI timeout, unavailable model or invalid JSON |
| A2 / P1–P2 | After A1 | Focused AI explanations for DNS, TLS, HTTP and CDN | Only call AI when explicitly requested, preferably after deterministic explanations; do not reclassify NXDOMAIN/RCODE, certificate verification or HTTP response codes using model output |
| A3 / P2 | Later | `netkit ask "natural language request"` to produce a `DiagnosticPlan` | Shared AI API client but a separate planner prompt/schema; preview and validate target, ports, tool whitelist, timeouts, request limits and scope; ask for missing host/port rather than guessing; never execute model-written shell strings |
| A4 / P2–P3 | Later | Compare reports across separate runs | Compare real stored evidence and timestamps, report differences without inventing history or outages |
| A5 / P3 | Optional | Suggested/approved further probes | No unbounded autonomous scanning; explicit user approval and restrictive command/target allowlist before any additional probe; no `sh -c` or arbitrary command execution |

### CLI input strategy and examples (proposed, NOT available yet)

1. **Deterministic CLI parser** remains the primary path. Parsing IPs, port numbers, `-timeout`, `--output`, scope validation and clear error messages must not invoke AI. Preserve existing shortcuts and exit/JSON compatibility.
2. **Simple default diagnosis** should cover common user intent without extra flags: `netkit diagnose example.com`. Put advanced checks behind explicit options, not implicit model choices. Consider allowing flags before or after positional targets, and shell completion, using ordinary deterministic parsing rather than an LLM.
3. **Natural-language entrypoint** is distinct and later: `netkit ask "检查 example.com 为什么访问慢"`. AI generates *data*, not a shell command; convert the output to a typed and validated `DiagnosticPlan` and show a preview before executing anything.
4. **Opt-in explanation** can be requested independently: `netkit diagnose example.com --ai`; keep no-AI output complete and useful.

### Uniform AI transport and configuration

- Target lowest common compatible HTTP endpoint `/v1/chat/completions` with Go `net/http`; define one model-independent request/response abstraction. Base URL examples: `http://127.0.0.1:11434/v1` for Ollama and `https://api.openai.com/v1` for commercial services. Other Qwen-compatible services or NewAPI use the same client via configuration.
- Proposed configuration keys: `NETKIT_AI_BASE_URL`, `NETKIT_AI_MODEL`, `NETKIT_AI_API_KEY` (never log or persist secrets), `NETKIT_AI_TIMEOUT`. Allow HTTP by default only for loopback-local inference; require HTTPS for remote endpoints and avoid unexpected redirects to unsafe endpoints.
- Model behavior differences (JSON-schema enforcement, streaming, reasoning/thinking fields, tool calls) must be capability-checked; start with non-streaming, bounded Chat Completions requests and strict locally validated output.
- Default AI **disabled**. AI failures should preserve the deterministic report and record optional `ai_error`; do not convert a successful network diagnosis into a general CLI failure merely because an AI API is unavailable.
- Scope and privacy: minimize and redact sensitive URLs/query parameters, authorization and cookie headers, tokens, internal IPs and hostnames before any external API call; sending private topology requires an explicit opt-in. Treat DNS TXT, HTTP headers/bodies and model-generated text as untrusted content, not tool instructions.
- Establish a small labeled regression corpus (at least 20–30 cases: DNS NXDOMAIN/SERVFAIL/disagreements, TCP partial failure, TLS mismatch/expiration, HTTP 403/429/redirect/timeout, CDN ambiguity) to assess attribution, valid evidence citations, hallucinations, latency and graceful fallback across local and cloud models.

### AI's permitted role by diagnostic layer

- **No AI** for raw DNS/TCP/TLS/HTTP measurements, validation, default statuses or security-sensitive command parsing.
- **P0 AI value**: explain correlated multi-layer results and prioritize evidence-backed next steps *after* A0 is working.
- **P1 specialty**: DNS resolver differences and DNSSEC uncertainty; TLS SAN/SNI, expiry and chain guidance; HTTP TTFB/redirect/restriction; CDN CNAME-vs-header evidence. Missing signals remain unknown, and no single probe proves global availability.
- **Optional later**: explain IP/WHOIS/ASN provenance and changes between timestamped runs; deterministic explanations should be used for common errors where sufficient.

**Release invariant:** development of any of the above must not create a formal version Tag or mutate `will-opz/homebrew-tap`. Only explicitly tagged, verified GitHub Releases can precede a separate Homebrew update.

### A0 deterministic diagnostic implementation (2026-11-20)

- [x] `netkit diagnose HOST|URL`: validated hostname/IP/HTTP(S) root target, default HTTPS, optional port, bounded DNS → TCP → TLS → HTTP checks.
- [x] JSON `EvidenceBundle` schema v1 with observer, timestamp, `DiagnosticPlan`, stage IDs, stage evidence and first confirmed failing layer; English keys and bilingual terminal summary.
- [x] Deterministic `failed`, `degraded` and `skipped` stages; preserve raw TCP/TLS/HTTP result structs without changing existing commands; no AI calls.
- [x] Mocked/isolated offline tests for valid/invalid targets, sequential stage failures, restricted HTTP, consistent evidence IDs and JSON; CI smoke test with local loopback target.
- [x] A1 initial implementation: one OpenAI-compatible Chat Completions client for OpenAI/local Qwen/NewAPI, environment-only API key, explicit `-ai` opt-in, sanitized evidence, evidence-ID validation, and graceful `ai_error` fallback.
- [ ] A1 field validation: test against real authorized OpenAI and Qwen model IDs/response behavior, evaluate quality on labeled 20–30 case corpus, and consider JSON schema capability negotiation per provider. No real API credentials are committed.
- [ ] A0 follow-up: explicit per-IP pinning across DNS/TCP/TLS/HTTP for comparable CDN/backend tracing; current independent TLS/HTTP probes can reach different resolved IPs.

Use `netkit diagnose --output json example.com` to inspect the evidence contract before A1.

### OpenAI-compatible A1 transport (2026-11-20)

- [x] `netkit diagnose -ai TARGET` runs deterministic probes first, then optionally obtains a separate AI explanation. `ai_analysis` cannot change first-failure classification or network evidence.
- [x] Default API base URL: `https://api.openai.com/v1`; compatible local Ollama and NewAPI selected via `NETKIT_AI_BASE_URL`, `NETKIT_AI_MODEL`, `NETKIT_AI_API_KEY`. No key embedded in source. Local loopback inference supports HTTP without a key; remote transport requires HTTPS and a key.
- [x] AI payload allowlist, private/internal target guard for remote API, response length and field checks, validation of evidence IDs, disabled redirects and isolated `ai_error` on errors.
- [x] Local `httptest` fixtures for compatible JSON Chat Completions response, privacy, missing key and invalid evidence references.
- [ ] Real API integration requires a locally configured authorized API key and explicit acceptance testing; evaluate responses for different model families before declaring production-ready.

The Homebrew Tap remains unchanged until a separately approved, verified tagged release.
