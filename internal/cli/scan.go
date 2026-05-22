package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/rad-security/image-scanner/internal/enrich"
	"github.com/rad-security/image-scanner/internal/grype"
	"github.com/rad-security/image-scanner/internal/imageref"
	"github.com/rad-security/image-scanner/internal/rad"
	"github.com/rad-security/image-scanner/internal/report"
)

// runScan is the cobra RunE. Because root.DisableFlagParsing = true, args is
// the full argv after the binary name.
func runScan(_ *cobra.Command, args []string) error {
	ctx := context.Background()

	rf, passThrough, err := extractRadFlags(args)
	if err != nil {
		return err
	}

	grypeVersion := grype.PinnedVersion
	if rf.grypeVersion != "" {
		grypeVersion = strings.TrimPrefix(rf.grypeVersion, "v")
	}

	// Intercept --help / --version / --rad-grype-help before passthrough so
	// the user sees the scanner's own usage rather than only grype's.
	if rf.grypeHelp {
		return printGrypeHelp(ctx, grypeVersion)
	}
	if hasHelpFlag(args) {
		printHelp(grypeVersion)
		return nil
	}
	if hasVersionFlag(args) {
		printVersion(grypeVersion)
		return nil
	}

	cfg := rad.ConfigFromEnv()
	if rf.accountIDsCSV != "" {
		cfg.AccountIDs = splitCSV(rf.accountIDsCSV)
	}
	if rf.apiURL != "" {
		cfg.APIURL = rf.apiURL
	}
	radActive := !rf.skipRAD && cfg.Enabled() && len(cfg.AccountIDs) > 0
	binPath, err := grype.Locate(ctx, grypeVersion)
	if err != nil {
		return fmt.Errorf("locating grype %s: %w", grypeVersion, err)
	}

	// Fast path: no RAD enrichment — just exec grype transparently.
	if !radActive {
		code, err := grype.Run(ctx, binPath, passThrough, os.Stdout, os.Stderr)
		if err != nil {
			return err
		}
		if code != 0 {
			os.Exit(code)
		}
		return nil
	}

	// RAD path. Inject -o json=<temp> so we can parse counts, then run grype.
	tmpJSON, err := os.CreateTemp("", "rad-image-scanner-*.json")
	if err != nil {
		return fmt.Errorf("creating temp json: %w", err)
	}
	tmpJSON.Close()
	defer os.Remove(tmpJSON.Name())

	finalArgs := append([]string{}, passThrough...)
	// Grype suppresses its default stdout table once any -o is given, so if
	// the user did not request an output format we re-add table explicitly —
	// otherwise injecting -o json=<temp> would leave the terminal empty.
	if !hasOutputFlag(passThrough) {
		finalArgs = append(finalArgs, "-o", "table")
	}
	finalArgs = append(finalArgs, "-o", "json="+tmpJSON.Name())

	code, err := grype.Run(ctx, binPath, finalArgs, os.Stdout, os.Stderr)
	if err != nil {
		return err
	}

	// Read grype JSON.
	jsonFile, err := os.Open(tmpJSON.Name())
	if err != nil {
		return fmt.Errorf("opening grype output: %w", err)
	}
	scan, parseErr := enrich.ParseGrypeScan(jsonFile)
	jsonFile.Close()
	if parseErr != nil {
		// Grype produced no parseable output. If it also exited non-zero it
		// has already printed a clear diagnostic to stderr — exit with its
		// code rather than stacking a confusing JSON-parse error on top.
		if code != 0 {
			os.Remove(tmpJSON.Name())
			fmt.Fprintln(os.Stderr, "RAD: scan engine failed (see error above) — enrichment skipped")
			os.Exit(code)
		}
		return fmt.Errorf("grype produced no parseable output: %w", parseErr)
	}

	// Resolve image identity for inventory lookup.
	target := findTarget(passThrough)
	if target == "" {
		return fmt.Errorf("could not identify scan target in arguments")
	}
	ref, err := imageref.FromTarget(target)
	if err != nil {
		return fmt.Errorf("resolving image identity: %w", err)
	}
	if rf.imageNameOverride != "" {
		ref.Name = rf.imageNameOverride
	}
	if rf.imageRepoOverride != "" {
		ref.Repo = rf.imageRepoOverride
	}
	if ref.Name == "" {
		return fmt.Errorf("RAD enrichment requires an image name")
	}

	// Fetch deployed instances and their placement (clusters / namespaces /
	// workloads) from the inventory.
	client := rad.NewClient(cfg)
	deployed, err := client.FindDeployed(ctx, ref.Name, ref.Repo)
	if err != nil {
		return fmt.Errorf("fetching deployed images: %w", err)
	}
	if err := client.AttachPlacement(ctx, deployed); err != nil {
		return fmt.Errorf("fetching deployment placement: %w", err)
	}

	// Diff against deployed instances.
	comparisons := enrich.CompareAll(scan.Counts, deployed)

	rep := report.Report{
		GeneratedAt: time.Now().UTC(),
		Image:       report.FromRef(ref),
		GrypeSummary: report.GrypeSummaryBlock{
			GrypeVersion: grypeVersion,
			Counts:       scan.Counts,
			DistroEOL:    scan.DistroEOL,
		},
		RAD: &report.RADBlock{
			AccountIDs:     cfg.AccountIDs,
			Deployments:    comparisons,
			OverallVerdict: report.OverallVerdict(comparisons),
		},
	}

	// Write standalone RAD report. Unless the user pinned a path with
	// --rad-report, the filename is unique per run (image name + timestamp)
	// so successive scans do not overwrite each other.
	reportPath := rf.report
	if reportPath == "" {
		reportPath = defaultReportPath(ref.Name, rep.GeneratedAt)
	}
	if err := report.WriteJSON(reportPath, rep); err != nil {
		return err
	}

	// Human-readable summary to stderr so the RAD enrichment is visible even
	// when grype's own output is redirected to a file.
	renderEnrichment(os.Stderr, rep, reportPath)

	// Annotate SARIF if requested and a SARIF output is present.
	if rf.annotateSarif {
		if sarifPath := findSarifOutput(passThrough); sarifPath != "" {
			if err := report.AnnotateSARIF(sarifPath, rep); err != nil {
				return fmt.Errorf("annotating sarif: %w", err)
			}
		} else {
			fmt.Fprintln(os.Stderr, "warning: --rad-annotate-sarif requested but no -o sarif=<file> output found in grype args")
		}
	}

	// Gating: regression and EOL can each force a non-zero exit.
	failed := code != 0
	if rf.failOnRegression != "" {
		floor, err := enrich.ParseSeverityFloor(rf.failOnRegression)
		if err != nil {
			return err
		}
		if hit, idx := enrich.RegressionAt(comparisons, floor); hit {
			d := comparisons[idx].Deployed
			fmt.Fprintf(os.Stderr, "RAD: regression at floor=%s detected vs deployment in account %s (digest %s)\n",
				floor, d.AccountID, shortDigest(d.Digest))
			failed = true
		}
	}
	if rf.failOnEol && scan.DistroEOL != nil {
		fmt.Fprintf(os.Stderr, "RAD: scanned image is built on an end-of-life distro (%s)\n",
			scan.DistroEOL.Distro())
		failed = true
	}

	if failed {
		if code == 0 {
			os.Exit(1)
		}
		os.Exit(code)
	}
	return nil
}

// defaultReportPath builds a per-run report filename: rad-report-<name>-<ts>.json
func defaultReportPath(name string, ts time.Time) string {
	return fmt.Sprintf("rad-report-%s-%s.json", sanitizeForFilename(name), ts.Format("20060102-150405"))
}

func sanitizeForFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	if b.Len() == 0 {
		return "image"
	}
	return b.String()
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func shortDigest(d string) string {
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

// findSarifOutput inspects grype-bound args and returns the file path of a
// SARIF output, or "" if none was specified.
func findSarifOutput(argv []string) string {
	// Supported forms (matching grype's CLI):
	//   -o sarif=path.sarif
	//   -o sarif --file path.sarif
	//   --output sarif=path.sarif
	//   --output sarif --file path.sarif
	wantFile := false
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "-o" || a == "--output":
			if i+1 >= len(argv) {
				return ""
			}
			i++
			next := argv[i]
			if fmt, file, hasEq := strings.Cut(next, "="); hasEq {
				if fmt == "sarif" {
					return file
				}
			} else if next == "sarif" {
				wantFile = true
			}
		case (a == "--file" || a == "-f") && wantFile:
			if i+1 < len(argv) {
				return argv[i+1]
			}
		}
	}
	// SARIF requested without --file — grype writes to stdout, which we
	// can't easily annotate post-hoc. Treat as not present.
	return ""
}
