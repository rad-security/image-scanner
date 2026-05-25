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
docker run --rm ghcr.io/rad-security/image-scanner:latest <image>
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
rad-image-scanner alpine:3.23 -o sarif --file alpine.sarif
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

rad-image-scanner nginx:stable-alpine3.23 \
    -o sarif --file svc.sarif \
    --rad-annotate-sarif \
    --rad-fail-on-regression=critical \
    --rad-fail-on-eol


 ✔ Loaded image                                                           nginx:stable-alpine3.23
 ✔ Parsed image           sha256:ef5d6a03fb49fbc0f7ec6dc8e0f53ba5084b105aa327e061d6e17423c6ad3ffe
 ✔ Cataloged contents            b3ef1348ce35b68960bc265b9e355986dd62b7018ce80574ad0f65356e23f915
   ├── ✔ Packages                        [71 packages]
   ├── ✔ File metadata                   [979 locations]
   ├── ✔ Executables                     [126 executables]
   └── ✔ File digests                    [979 files]
 ✔ Scanned for vulnerabilities     [16 vulnerability matches]
   ├── by severity: 0 critical, 4 high, 12 medium, 0 low, 0 negligible
   └── by status:   0 fixed, 16 not-fixed, 0 ignored
NAME           INSTALLED   TYPE  VULNERABILITY   SEVERITY  EPSS           RISK
tiff           4.7.1-r0    apk   CVE-2023-6277   Medium    3.8% (88th)    2.2
tiff           4.7.1-r0    apk   CVE-2023-52356  High      0.7% (72nd)    0.5
curl           8.19.0-r0   apk   CVE-2026-7168   Medium    < 0.1% (23rd)  < 0.1
busybox        1.37.0-r30  apk   CVE-2025-60876  Medium    < 0.1% (15th)  < 0.1
busybox-binsh  1.37.0-r30  apk   CVE-2025-60876  Medium    < 0.1% (15th)  < 0.1
ssl_client     1.37.0-r30  apk   CVE-2025-60876  Medium    < 0.1% (15th)  < 0.1
tiff           4.7.1-r0    apk   CVE-2026-4775   High      < 0.1% (11th)  < 0.1
curl           8.19.0-r0   apk   CVE-2026-5545   Medium    < 0.1% (15th)  < 0.1
curl           8.19.0-r0   apk   CVE-2026-6253   Medium    < 0.1% (12th)  < 0.1
curl           8.19.0-r0   apk   CVE-2026-5773   High      < 0.1% (7th)   < 0.1
curl           8.19.0-r0   apk   CVE-2026-6429   Medium    < 0.1% (7th)   < 0.1
curl           8.19.0-r0   apk   CVE-2026-6276   High      < 0.1% (5th)   < 0.1
curl           8.19.0-r0   apk   CVE-2026-4873   Medium    < 0.1% (4th)   < 0.1
freetype       2.14.1-r0   apk   CVE-2026-23865  Medium    < 0.1% (4th)   < 0.1
tiff           4.7.1-r0    apk   CVE-2023-6228   Medium    < 0.1% (3rd)   < 0.1
curl           8.19.0-r0   apk   CVE-2026-7009   Medium    < 0.1% (1st)   < 0.1

  ██████╗  █████╗ ██████╗
  ██╔══██╗██╔══██╗██╔══██╗
  ██████╔╝███████║██║  ██║
  ██╔══██╗██╔══██║██║  ██║
  ██║  ██║██║  ██║██████╔╝
  ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   SECURITY · IMAGE SCANNER ENRICHMENT REPORT
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  Image: nginx:stable-alpine3.23
  Scan:  0 critical  4 high  12 medium  0 low  0 negligible  0 unknown   (16 total)

  Deployed instances (2 across 1 account(s))

  ACCOUNT                     DIGEST        DISTRO          EOL       CRITICAL   HIGH       MEDIUM     LOW        VERDICT
  2IAtTppYqpVGxSdkBWW5n7zYzVU 1eadbb078203  alpine:3.20.6   reached   5 (-5)     51 (-47)   60 (-48)   10 (-10)   improvement
  2IAtTppYqpVGxSdkBWW5n7zYzVU 33001975a6ea  alpine:3.19.3   reached   6 (-6)     51 (-47)   60 (-48)   16 (-16)   improvement

  Placement — where this image runs

    1eadbb078203  1 container(s) · 1 cluster(s) · 1 namespace(s)
      clusters:   pe-prd-us-west-2
      namespaces: default
      workloads:  Pod/nginx-7

    33001975a6ea  1 container(s) · 1 cluster(s) · 1 namespace(s)
      clusters:   pe-prd-us-west-2
      namespaces: default
      workloads:  Pod/nginx-6

  Overall verdict: improvement
  Report:          rad-report-nginx-20260522-135531.json

  ✓  BETTER — this image has fewer vulnerabilities than every deployed instance. Safe to roll out.
```

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
