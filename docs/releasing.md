# NetKit Release Playbook

## Current status

Release tooling is prepared in the repository. **Creating a development commit or dispatching a dry-run does not publish a release, create a tag, or update `will-opz/homebrew-tap`.** The first official version must be explicitly selected by the maintainer after checking versioning and licensing.

## Review before the first official release

1. Select and document the project's own source license. The embedded Public Suffix List data is MPL-2.0 and retains its upstream notice; this does **not** automatically license NetKit's Go code. At the time this playbook was written, this repository had no top-level `LICENSE`. Obtain maintainer choice before adding one or distributing a public binary.
2. Review [CHANGELOG.md](../CHANGELOG.md), the release number and compatibility impact (especially JSON fields and process exit codes).
3. Confirm the current default branch's GitHub Actions matrix is green (macOS and Ubuntu, plus Windows/ARM cross-compilation).
4. Verify tools with `netkit version`, `netkit dns compare`, `netkit tls`, `netkit http`, `netkit tcp` and `netkit domain`.
5. Optionally run a **dry-run** locally or by manually dispatching the Release workflow. Both generate packages for inspection **without** publishing or updating the Tap.

## Reproducible dry-run packaging

From a clean checked-out commit, with Go 1.23+ and Python 3:

```bash
go test ./...
go vet ./...
go run ./cmd/netkit version
python3 scripts/package_release.py --version dev --output dist
python3 scripts/check_release.py --version dev --dist dist
(cd dist && sha256sum -c checksums.txt)  # Linux; macOS use shasum -a 256 -c
```

The output directory must start empty. The script creates:

```text
netkit_dev_linux_amd64.tar.gz
netkit_dev_linux_arm64.tar.gz
netkit_dev_darwin_amd64.tar.gz
netkit_dev_darwin_arm64.tar.gz
netkit_dev_windows_amd64.zip
checksums.txt
```

Archive members include the platform binary, README and the vendored PSL file (with its own MPL-2.0 notice). The script strips paths and VCS build settings for reproducibility and fixes archive metadata/timestamps; byte-for-byte reproducibility still requires the same Go toolchain and source commit. The version and the first twelve characters of the source commit are injected into binaries at build time.

## Official release (maintainer-initiated only)

After selecting version `vX.Y.Z`, verifying the source license and finalizing the changelog:

1. Create and push the **annotated** tag on the reviewed commit, e.g. `git tag -a vX.Y.Z -m "NetKit vX.Y.Z"` and `git push origin vX.Y.Z`.
2. The Release workflow's `push.tags: v*` trigger builds the same five release packages, runs tests, verifies SHA256 and contents, then creates a GitHub Release for that **existing** tag using `gh release create --verify-tag`. It never creates a tag.
3. Verify the published GitHub Release and asset download/checksums against `checksums.txt`. Inspect `netkit version` from a downloaded package and confirm the version/commit.
4. **Only after successful formal tag + GitHub Release + verification**, update `will-opz/homebrew-tap` to the immutable release asset and its exact SHA256, then test `brew install/upgrade will-opz/tap/netkit`. No Tap updates on ordinary commits, dry runs, or failed releases.

The publishing workflow intentionally **does not touch Homebrew Tap**. That separate post-release step needs a distinct review/authorization and credentials. A failed release build blocks publication. If a release is already present for the tag, the workflow refuses to overwrite it.

## Limitations

- This is an unsigned build and archive/checksum workflow, not code signing or notarization. Apple Gatekeeper experience must be validated separately.
- Windows binaries are compile-checked but not tested on Windows hosts; Windows packaging is a ZIP.
- No Linux package manager, Windows installer, provenance attestation, or automatic formula change is added.
- Avoid embedding credentials in binaries or GitHub workflows.
