# Changelog

All notable changes are recorded here in development. Official versions are created only on a reviewed version tag.

## Unreleased

### Added
- Local network, IP, GeoIP, WHOIS, RDAP, reverse DNS, BGP, CIDR and bounded stdin diagnostics.
- Domain apex/www availability, CDN evidence, RDAP, and detailed DNS records.
- DNS system resolver listing, public DNS catalog, resolver comparison and opt-in DoH RCODE/TTL/record comparison.
- Standalone TCP, TLS and HTTP diagnosis with per-address checks, certificate verification error codes and per-hop HTTP timing.
- Offline Mozilla Public Suffix List with wildcard, exception and private-suffix handling.
- Build metadata via `netkit version` and release-package dry-run tooling.

### Reliability and workflow
- Local deterministic tests for network failures and JSON output contracts.
- CI on macOS and Ubuntu with additional platform cross-compilation.
- Multi-platform release archives and SHA256 manifest; official GitHub Releases will only be generated from valid pushed version tags.
- Homebrew Tap update remains a **separate, post-verification step after formal tagged release**, never part of regular development commits.

Do not replace this section with a version number until the corresponding tag/release is actually created.
