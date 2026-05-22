package cli

import (
	"context"
	"fmt"
	"os"
	"slices"

	"github.com/rad-security/image-scanner/internal/grype"
)

func hasHelpFlag(args []string) bool {
	return slices.Contains(args, "--help") || slices.Contains(args, "-h")
}

func hasVersionFlag(args []string) bool {
	return slices.Contains(args, "--version")
}

const radHelp = `rad-image-scanner — container image vulnerability scanner

Wraps Grype and, when RAD Security credentials are configured, enriches the
scan with currently-deployed image data, regression detection, distro EOL
warnings, and Kubernetes deployment placement.

USAGE
  rad-image-scanner [rad-flags] [engine-flags] <image | sbom:path>

RAD ENRICHMENT
  Enrichment is active only when RAD_ACCESS_KEY_ID, RAD_SECRET_KEY and
  RAD_ACCOUNT_IDS are set. Without them the scanner behaves exactly like Grype.

RAD FLAGS
  --rad-report PATH               Write the RAD enrichment JSON report.
                                  Default: rad-report-<image>-<timestamp>.json
  --rad-annotate-sarif            Inject the RAD report into SARIF output
                                  under runs[].properties.rad.
  --rad-fail-on-regression LEVEL  Exit non-zero if the scan adds vulnerabilities
                                  at this severity or higher vs any deployed
                                  instance (critical|high|medium|low|any).
  --rad-fail-on-eol               Exit non-zero if the scanned image is built
                                  on an end-of-life distro (per Grype).
  --rad-account-ids IDS           Comma-separated account IDs (overrides env).
  --rad-api-url URL               RAD API base URL (default https://api.rad.security).
  --rad-image-name NAME           Override the image name used for RAD lookup.
  --rad-image-repo REPO           Override the image repo used for RAD lookup.
  --rad-grype-version VER         Pin a different Grype version at runtime.
  --rad-grype-help                Print Grype's full, unmodified help and exit.
  --rad-skip                      Disable RAD enrichment even if env is set.

ENGINE FLAGS (most common — provided by the Grype engine)
  -o, --output FORMAT[=FILE]      Output format, repeatable. One of: table,
                                  json, cyclonedx, sarif, template.
                                  e.g. -o table -o sarif=report.sarif
  --fail-on SEVERITY              Exit non-zero on a vulnerability at or above
                                  this severity (negligible|low|medium|high|critical).
  -s, --scope SCOPE               Image layers to inspect: squashed (default)
                                  or all-layers.
  --exclude PATTERN               Glob of in-image paths to exclude from scanning.
  -c, --config PATH               Grype config file — also where CVE ignore
                                  rules are declared.
  --platform PLATFORM             Platform of a multi-arch image, e.g. linux/arm64.
  --add-cpes-if-none              Generate CPEs for packages that have none,
                                  improving match coverage.
  --by-cve                        Orient results around CVE IDs rather than the
                                  originating vendor advisory.
  --only-fixed                    Report only vulnerabilities that have a fix.
  --distro DISTRO                 Force the distro used for matching, e.g.
                                  alpine:3.20.

  Run with --rad-grype-help for the complete, unmodified Grype flag list.
  Any flag not listed above is passed through to the engine unchanged.

ENVIRONMENT
  RAD_ACCESS_KEY_ID, RAD_SECRET_KEY, RAD_ACCOUNT_IDS, RAD_API_URL
  RAD_GRYPE_PATH   Use a specific Grype binary instead of locating/downloading.
  NO_COLOR         Disable colored output.
`

// printHelp writes the scanner's own curated help. The big "RAD" banner is
// shown first; the scan engine is credited in an attribution footer.
func printHelp(grypeVersion string) {
	p := newPalette(os.Stdout)
	fmt.Fprintln(os.Stdout)
	for _, line := range radBlockArt {
		fmt.Fprintln(os.Stdout, p.cyan(line))
	}
	fmt.Fprintln(os.Stdout)
	fmt.Fprint(os.Stdout, radHelp)
	fmt.Fprintln(os.Stdout)
	fmt.Fprintf(os.Stdout, "Scan engine: Grype v%s by Anchore, Inc. — https://github.com/anchore/grype (Apache-2.0)\n", grypeVersion)
}

// printGrypeHelp prints Grype's own, unmodified help (--rad-grype-help).
func printGrypeHelp(ctx context.Context, grypeVersion string) error {
	binPath, err := grype.Locate(ctx, grypeVersion)
	if err != nil {
		return fmt.Errorf("locating grype %s: %w", grypeVersion, err)
	}
	fmt.Fprintf(os.Stdout, "Raw engine help — Grype v%s (https://github.com/anchore/grype)\n\n", grypeVersion)
	if _, err := grype.Run(ctx, binPath, []string{"--help"}, os.Stdout, os.Stderr); err != nil {
		return fmt.Errorf("running grype help: %w", err)
	}
	return nil
}

// printVersion shows both the scanner version and the Grype engine version.
func printVersion(grypeVersion string) {
	fmt.Fprintf(os.Stdout, "rad-image-scanner %s (commit %s)\n", version, commit)
	fmt.Fprintf(os.Stdout, "grype %s (vulnerability engine)\n", grypeVersion)
}
