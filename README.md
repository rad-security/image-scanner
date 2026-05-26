# rad-image-scanner

A container image vulnerability scanner, when [RAD Security](https://rad.security) credentials are configured, enriches the report with information about the image as it is *currently deployed* in your fleet — vulnerability count deltas, regression detection, and distro EOL warnings.

## Installation

### Homebrew (macOS / Linuxbrew)

```sh
brew install rad-security/tap/rad-image-scanner
```

### Linux (curl + tar)

Download and install the latest binary into `/usr/local/bin`:

```sh
VERSION=$(curl -fsSL https://api.github.com/repos/rad-security/image-scanner/releases/latest | grep -oE '"tag_name": "v[^"]+"' | cut -d'"' -f4 | sed 's/^v//')
ARCH=$(uname -m); case "$ARCH" in x86_64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; esac
curl -fsSL "https://github.com/rad-security/image-scanner/releases/download/v${VERSION}/rad-image-scanner_${VERSION}_linux_${ARCH}.tar.gz" \
  | sudo tar -xz -C /usr/local/bin rad-image-scanner
rad-image-scanner --version
```

For macOS, swap `linux` for `darwin` in the URL.

### Docker

```sh
docker run --rm public.ecr.aws/n8h5y2v5/rad-security/rad-image-scanner:latest <image>
```

### Binary releases (manual)

Download the archive for your platform from the [releases page](https://github.com/rad-security/image-scanner/releases) and place `rad-image-scanner` on your `PATH`.

### From source

```sh
go install github.com/rad-security/image-scanner@latest
```

## Modes

### Pure passthrough — no RAD env

If `RAD_ACCESS_KEY_ID` and `RAD_SECRET_KEY` are unset, `rad-image-scanner` behaves identically to `grype`. Every argument is forwarded, output is unchanged, and the exit code is grype's.

```sh
rad-image-scanner alpine:3.23
```

### RAD-enriched

With the following environment variables, the scanner also queries the RAD Security inventory for every configured account, compares severity counts, and writes an enrichment report.

| Variable | Required | Description |
|---|---|---|
| `RAD_ACCESS_KEY_ID` | yes | Access key ID from RAD Security |
| `RAD_SECRET_KEY` | yes | Secret matching the access key |
| `RAD_ACCOUNT_IDS` | yes | Comma-separated list of account IDs to query |
| `RAD_API_URL` | no | Defaults to `https://api.rad.security` |

```sh
export RAD_ACCESS_KEY_ID=...
export RAD_SECRET_KEY=...
export RAD_ACCOUNT_IDS=acct_1,acct_2
rad-image-scanner public.ecr.aws/n8h5y2v5/rad-security/rad-sbom:v1.1.63
 ✔ Loaded image                                                                            public.ecr.aws/n8h5y2v5/rad-security/rad-sbom:v1.1.63
 ✔ Parsed image                                                          sha256:75ae68d3c6bed4e29c8f2cdc7d843495c48c39498bc0040b16d77acbf3063759
 ✔ Cataloged contents                                                           c90f526ca7ee5cb902f18c2d752627863d9725f0c714c3ddf791e9489caabe3b
   ├── ✔ Packages                        [367 packages]
   ├── ✔ Executables                     [1 executables]
   ├── ✔ File metadata                   [934 locations]
   └── ✔ File digests                    [934 files]
 ✔ Scanned for vulnerabilities     [35 vulnerability matches]
   ├── by severity: 1 critical, 18 high, 14 medium, 2 low, 0 negligible
   └── by status:   35 fixed, 0 not-fixed, 0 ignored
NAME                                                   INSTALLED  FIXED IN         TYPE       VULNERABILITY        SEVERITY  EPSS           RISK
stdlib                                                 go1.26.1   1.25.10, 1.26.3  go-module  CVE-2026-39820       High      < 0.1% (16th)  < 0.1
github.com/go-git/go-git/v5                            v5.17.0    5.18.0           go-module  GHSA-3xc5-wrhm-f963  Medium    < 0.1% (17th)  < 0.1
github.com/go-jose/go-jose/v4                          v4.1.3     4.1.4            go-module  GHSA-78h2-9frx-2jm8  High      < 0.1% (10th)  < 0.1
stdlib                                                 go1.26.1   1.25.9, 1.26.2   go-module  CVE-2026-27143       Critical  < 0.1% (6th)   < 0.1
stdlib                                                 go1.26.1   1.25.9, 1.26.2   go-module  CVE-2026-32281       High      < 0.1% (6th)   < 0.1
stdlib                                                 go1.26.1   1.25.10, 1.26.3  go-module  CVE-2026-42499       High      < 0.1% (6th)   < 0.1
stdlib                                                 go1.26.1   1.25.9, 1.26.2   go-module  CVE-2026-32280       High      < 0.1% (6th)   < 0.1
stdlib                                                 go1.26.1   1.25.10, 1.26.3  go-module  CVE-2026-39836       High      < 0.1% (5th)   < 0.1
stdlib                                                 go1.26.1   1.25.9, 1.26.2   go-module  CVE-2026-32283       High      < 0.1% (5th)   < 0.1
stdlib                                                 go1.26.1   1.25.10, 1.26.3  go-module  CVE-2026-33814       High      < 0.1% (5th)   < 0.1
stdlib                                                 go1.26.1   1.25.10, 1.26.3  go-module  CVE-2026-33811       High      < 0.1% (4th)   < 0.1
stdlib                                                 go1.26.1   1.25.9, 1.26.2   go-module  CVE-2026-27140       High      < 0.1% (3rd)   < 0.1
github.com/hashicorp/go-getter                         v1.8.5     1.8.6            go-module  GHSA-92mm-2pjq-r785  High      < 0.1% (3rd)   < 0.1
stdlib                                                 go1.26.1   1.26.2           go-module  CVE-2026-33810       High      < 0.1% (2nd)   < 0.1
go.opentelemetry.io/otel/sdk                           v1.41.0    1.43.0           go-module  GHSA-hfvc-g4fc-pqhx  High      < 0.1% (1st)   < 0.1
stdlib                                                 go1.26.1   1.25.10, 1.26.3  go-module  CVE-2026-39826       Medium    < 0.1% (2nd)   < 0.1
stdlib                                                 go1.26.1   1.25.10, 1.26.3  go-module  CVE-2026-39825       Medium    < 0.1% (1st)   < 0.1
stdlib                                                 go1.26.1   1.25.9, 1.26.2   go-module  CVE-2026-32289       Medium    < 0.1% (1st)   < 0.1
stdlib                                                 go1.26.1   1.25.10, 1.26.3  go-module  CVE-2026-42501       High      < 0.1% (0th)   < 0.1
stdlib                                                 go1.26.1   1.25.9, 1.26.2   go-module  CVE-2026-32282       Medium    < 0.1% (1st)   < 0.1
stdlib                                                 go1.26.1   1.25.10, 1.26.3  go-module  CVE-2026-39823       Medium    < 0.1% (1st)   < 0.1
stdlib                                                 go1.26.1   1.25.10, 1.26.3  go-module  CVE-2026-39819       Medium    < 0.1% (0th)   < 0.1
stdlib                                                 go1.26.1   1.25.9, 1.26.2   go-module  CVE-2026-27144       High      < 0.1% (0th)   < 0.1
github.com/go-git/go-git/v5                            v5.17.0    5.17.1           go-module  GHSA-jhf3-xxhw-2wpp  Medium    < 0.1% (0th)   < 0.1
stdlib                                                 go1.26.1   1.25.10, 1.26.3  go-module  CVE-2026-39817       Medium    < 0.1% (0th)   < 0.1
stdlib                                                 go1.26.1   1.25.9, 1.26.2   go-module  CVE-2026-32288       Medium    < 0.1% (0th)   < 0.1
github.com/go-git/go-git/v5                            v5.17.0    5.17.1           go-module  GHSA-gm2x-2g9h-ccm8  Low       < 0.1% (0th)   < 0.1
github.com/containerd/containerd/v2                    v2.2.1     2.2.4            go-module  GHSA-fqw6-gf59-qr4w  High      N/A            N/A
github.com/go-git/go-billy/v5                          v5.8.0     5.9.0            go-module  GHSA-qw64-3x98-g7q2  High      N/A            N/A
github.com/go-git/go-git/v5                            v5.17.0    5.19.0           go-module  GHSA-389r-gv7p-r3rp  High      N/A            N/A
github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream  v1.7.4     1.7.8            go-module  GHSA-xmrv-pmrh-hhx2  Medium    N/A            N/A
github.com/aws/aws-sdk-go-v2/service/s3                v1.96.0    1.97.3           go-module  GHSA-xmrv-pmrh-hhx2  Medium    N/A            N/A
github.com/go-git/go-billy/v5                          v5.8.0     5.9.0            go-module  GHSA-m3xc-h892-ggx6  Medium    N/A            N/A
github.com/go-git/go-git/v5                            v5.17.0    5.19.1           go-module  GHSA-crhj-59gh-8x96  Medium    N/A            N/A
github.com/go-git/go-git/v5                            v5.17.0    5.19.1           go-module  GHSA-m7cr-m3pv-hgrp  Low       N/A            N/A

  ██████╗  █████╗ ██████╗
  ██╔══██╗██╔══██╗██╔══██╗
  ██████╔╝███████║██║  ██║
  ██╔══██╗██╔══██║██║  ██║
  ██║  ██║██║  ██║██████╔╝
  ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   SECURITY · IMAGE SCANNER ENRICHMENT REPORT
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  Image: public.ecr.aws/n8h5y2v5/rad-security/rad-sbom:v1.1.63
  Scan:  1 critical  18 high  14 medium  2 low  0 negligible  0 unknown   (35 total)

  Deployed instances (2 across 1 account(s))

  ACCOUNT                     DIGEST        DISTRO          EOL       CRITICAL   HIGH       MEDIUM     LOW        VERDICT
  2IAtTppYqpVGxSdkBWW5n7zYzVU d02822aa8630  debian:12       30-days   6 (-5)     33 (-15)   41 (-27)   7 (-5)     improvement
  2IAtTppYqpVGxSdkBWW5n7zYzVU 3c5b34816636  debian:13       ok        0 (+1)     9 (+9)     7 (+7)     1 (+1)     regression

  Placement — where this image runs

    d02822aa8630  1 container(s) · 1 cluster(s) · 1 namespace(s)
      clusters:   gke-cluster-standard
      namespaces: default
      workloads:  Pod/rad-sbom-7b75597cd7-s7kjm

    3c5b34816636  1 container(s) · 1 cluster(s) · 1 namespace(s)
      clusters:   pe-prd-us-west-2
      namespaces: rad
      workloads:  Pod/rad-sbom-59d64c769c-jgkkt

  Overall verdict: regression
  Report:          rad-report-rad-sbom-20260526-121159.json

  ✗  WORSE — this image adds vulnerabilities versus what is currently deployed. Review before rolling out.
```

## Use in CI (GitHub Action)

[`rad-security/image-scan-action`](https://github.com/rad-security/image-scan-action) is the same scanner wrapped as a GitHub Action. It scans an image (or a pre-built Syft SBOM), optionally enriches the report with currently-deployed inventory from RAD Security, and can fail the workflow on severity, regression vs deployed instances, or an end-of-life base distro.

Minimal — plain Grype scan, no RAD env:

```yaml
- uses: rad-security/image-scan-action@v1
  with:
    image: ghcr.io/${{ github.repository }}:${{ github.sha }}
    fail_on_severity: high
```

RAD-enriched — gate the PR on regression vs deployed images and upload SARIF to Code Scanning:

```yaml
- id: scan
  uses: rad-security/image-scan-action@v1
  with:
    image: ghcr.io/${{ github.repository }}:${{ github.sha }}
    format: sarif
    rad_account_ids: acct_1,acct_2
    rad_fail_on_regression: critical
    rad_fail_on_eol: "true"
  env:
    RAD_ACCESS_KEY_ID: ${{ secrets.RAD_ACCESS_KEY_ID }}
    RAD_SECRET_KEY: ${{ secrets.RAD_SECRET_KEY }}

- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: ${{ steps.scan.outputs.sarif }}
```

`RAD_ACCESS_KEY_ID` and `RAD_SECRET_KEY` go in `env:`, not `inputs:` — Actions inputs are visible in workflow logs; secrets in `env:` are masked.

Full input/output reference: [`rad-security/image-scan-action` README](https://github.com/rad-security/image-scan-action#readme).

## RAD-specific flags

| Flag | Description |
|---|---|
| `--rad-report PATH` | Write the standalone RAD enrichment JSON. Defaults to a per-run name `rad-report-<image>-<YYYYMMDD-HHMMSS>.json` so successive scans never overwrite each other. |
| `--rad-annotate-sarif` | When grype emits SARIF, inject the RAD report under `runs[].properties.rad`. |
| `--rad-fail-on-regression critical\|high\|medium\|low\|any` | Exit non-zero if the new scan adds vulnerabilities at this severity or higher vs *any* deployed instance. |
| `--rad-fail-on-eol` | Exit non-zero if the *scanned* image is built on an end-of-life distro (detected by Grype). |
| `--rad-account-ids id1,id2` | Override `RAD_ACCOUNT_IDS` env. |
| `--rad-api-url URL` | Override the RAD API base URL. |
| `--rad-image-name NAME` | Force the image *name* used for RAD lookup (useful when parsing is ambiguous). |
| `--rad-image-repo REPO/` | Force the image *repo* used for RAD lookup. |
| `--rad-grype-version VER` | Pin a different grype version at runtime (default is the version this build was tested against). |
| `--rad-grype-help` | Print Grype's full, unmodified help and exit. |
| `--rad-skip` | Disable RAD enrichment even if env is set. |

`rad-image-scanner --help` shows the scanner's own usage plus a curated list of the most common engine flags. The complete, unmodified Grype flag reference is available via `--rad-grype-help`. All flags not recognized as `--rad-*` are passed through to the Grype engine unchanged.

## How matching works

For each scan target the scanner extracts `name` and `repo` from the image reference (e.g. `registry/foo/bar/baz:v1` → `repo=registry/foo/bar/`, `name=baz`) and queries:

```
GET /accounts/{id}/data/scanned_images
    ?filters_query=name:"<name>" AND repo:"<repo>"
```

across every configured account in parallel. All returned deployments are merged and each one becomes a row in the enrichment report.

For each deployed image the scanner then queries the container inventory:

```
GET /accounts/{id}/inventory_containers
    ?filters=image_digest:<digest>
```

and aggregates the running containers into a **placement** block — container count, cluster names, namespaces, and the Kubernetes workloads (Pod/Deployment/...) running the image. This tells customers exactly *where* a scanned image is deployed. The placement block appears both in the terminal summary and under `rad.deployments[].deployed.placement` in the JSON report.

## Behaviour when RAD is unreachable

If `RAD_ACCESS_KEY_ID` and `RAD_SECRET_KEY` are set but authentication fails or the inventory API is unreachable, the scanner exits with a non-zero status. There is no silent fallback to pure-grype mode — this is intentional so that misconfigured CI surfaces loud failures rather than quietly losing the enrichment guarantee.

## Grype binary management

We do not embed grype. At runtime, the scanner:

1. Honours `$RAD_GRYPE_PATH` if set.
2. Looks for `grype` in `$PATH` and uses it if its version matches the pinned version.
3. Looks in `$XDG_CACHE_HOME/rad-image-scanner/grype-v<version>/grype`.
4. Downloads the official grype release tarball from GitHub, verifies the SHA256 against the published checksums file, extracts the binary into the cache, and uses that.

`--rad-grype-version` overrides the pinned version.

## License

Apache-2.0. Grype itself is © Anchore, Inc., distributed under Apache-2.0.
