package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rad-security/image-scanner/internal/enrich"
	"github.com/rad-security/image-scanner/internal/rad"
	"github.com/rad-security/image-scanner/internal/report"
)

// --- color palette ---------------------------------------------------------

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
)

type palette struct{ enabled bool }

// newPalette enables color only when writing to a terminal and NO_COLOR is
// unset (https://no-color.org).
func newPalette(w io.Writer) palette {
	if os.Getenv("NO_COLOR") != "" {
		return palette{false}
	}
	f, ok := w.(*os.File)
	if !ok {
		return palette{false}
	}
	fi, err := f.Stat()
	if err != nil {
		return palette{false}
	}
	return palette{fi.Mode()&os.ModeCharDevice != 0}
}

func (p palette) wrap(code, s string) string {
	if !p.enabled {
		return s
	}
	return code + s + ansiReset
}

func (p palette) bold(s string) string   { return p.wrap(ansiBold, s) }
func (p palette) dim(s string) string    { return p.wrap(ansiDim, s) }
func (p palette) red(s string) string    { return p.wrap(ansiRed, s) }
func (p palette) green(s string) string  { return p.wrap(ansiGreen, s) }
func (p palette) yellow(s string) string { return p.wrap(ansiYellow, s) }
func (p palette) cyan(s string) string   { return p.wrap(ansiCyan, s) }

func (p palette) verdict(v enrich.Verdict) string {
	s := string(v)
	switch v {
	case enrich.VerdictRegression:
		return p.red(s)
	case enrich.VerdictImprovement:
		return p.green(s)
	case enrich.VerdictMixed:
		return p.yellow(s)
	default:
		return p.dim(s)
	}
}

// eolStatus colorizes a (possibly already padded) EOL status string. The
// classification keys off the leading token so trailing padding is ignored.
func (p palette) eolStatus(padded string) string {
	switch strings.ToLower(strings.TrimSpace(padded)) {
	case "eol", "reached":
		return p.red(padded)
	case "30-days", "90-days":
		return p.yellow(padded)
	case "", "-":
		return p.dim(padded)
	default:
		return p.dim(padded)
	}
}

// --- enrichment summary rendering ------------------------------------------

type column struct {
	head  string
	width int
}

// tableColumns defines the deployment table layout. The banner width is
// derived from it so the header rule always spans the full table.
var tableColumns = []column{
	{"ACCOUNT", 28},
	{"DIGEST", 14},
	{"DISTRO", 16},
	{"EOL", 10},
	{"CRITICAL", 11},
	{"HIGH", 11},
	{"MEDIUM", 11},
	{"LOW", 11},
	{"VERDICT", 12},
}

func bannerWidth() int {
	w := 2 // leading indent
	for _, c := range tableColumns {
		w += c.width
	}
	return w
}

// radBlockArt is the ANSI-shadow block rendering of "RAD" used as the banner
// that separates grype's output from the RAD enrichment section.
var radBlockArt = []string{
	"  ██████╗  █████╗ ██████╗ ",
	"  ██╔══██╗██╔══██╗██╔══██╗",
	"  ██████╔╝███████║██║  ██║",
	"  ██╔══██╗██╔══██║██║  ██║",
	"  ██║  ██║██║  ██║██████╔╝",
	"  ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ",
}

// renderBanner draws the big "RAD" block banner.
func renderBanner(w io.Writer, p palette, rule string) {
	fmt.Fprintln(w)
	for _, line := range radBlockArt {
		fmt.Fprintln(w, p.cyan(line))
	}
	fmt.Fprintln(w, p.cyan(rule))
	fmt.Fprintln(w, "   "+p.bold("SECURITY · IMAGE SCANNER ENRICHMENT REPORT"))
	fmt.Fprintln(w, p.cyan(rule))
	fmt.Fprintln(w)
}

// renderEnrichment writes the human-readable RAD summary block to w.
func renderEnrichment(w io.Writer, rep report.Report, reportPath string) {
	p := newPalette(w)
	rb := rep.RAD
	rule := strings.Repeat("─", bannerWidth())

	renderBanner(w, p, rule)

	c := rep.GrypeSummary.Counts
	fmt.Fprintf(w, "  %s %s\n", p.dim("Image:"), p.bold(rep.Image.Input))
	fmt.Fprintf(w, "  %s %s\n", p.dim("Scan: "), severityLine(p, c))
	if eol := rep.GrypeSummary.DistroEOL; eol != nil {
		fmt.Fprintf(w, "  %s %s\n", p.dim("Distro:"),
			p.red(fmt.Sprintf("%s — END-OF-LIFE (vulnerability data may be incomplete)", eol.Distro())))
	}
	fmt.Fprintln(w)

	if len(rb.Deployments) == 0 {
		fmt.Fprintf(w, "  %s\n\n", p.yellow(fmt.Sprintf(
			"Image not found deployed in any of %d monitored account(s).", len(rb.AccountIDs))))
		fmt.Fprintf(w, "  %s %s\n", p.dim("Report:"), reportPath)
		fmt.Fprintln(w, p.cyan(rule))
		return
	}

	fmt.Fprintf(w, "  %s\n\n", p.bold(fmt.Sprintf(
		"Deployed instances (%d across %d account(s))", len(rb.Deployments), len(rb.AccountIDs))))
	renderDeploymentTable(w, p, rb.Deployments)
	fmt.Fprintln(w)

	renderPlacement(w, p, rb.Deployments)

	fmt.Fprintf(w, "  %s %s\n", p.dim("Overall verdict:"), p.verdict(rb.OverallVerdict))
	fmt.Fprintf(w, "  %s %s\n", p.dim("Report:         "), reportPath)

	fmt.Fprintln(w)
	renderHeadline(w, p, rb.OverallVerdict)
	fmt.Fprintln(w, p.cyan(rule))
}

// renderHeadline writes a single plain-language bottom line telling the
// customer whether the scanned image is better or worse than what is
// currently deployed.
func renderHeadline(w io.Writer, p palette, v enrich.Verdict) {
	var msg string
	switch v {
	case enrich.VerdictImprovement:
		msg = p.green("✓  BETTER — this image has fewer vulnerabilities than every deployed instance. Safe to roll out.")
	case enrich.VerdictRegression:
		msg = p.red("✗  WORSE — this image adds vulnerabilities versus what is currently deployed. Review before rolling out.")
	case enrich.VerdictMixed:
		msg = p.yellow("~  MIXED — some severities improve while others get worse. Review the table above before rolling out.")
	default:
		msg = p.dim("=  NO CHANGE — this image has the same vulnerability counts as what is currently deployed.")
	}
	fmt.Fprintf(w, "  %s\n", p.bold(msg))
}

func severityLine(p palette, c enrich.Counts) string {
	parts := []string{
		p.red(fmt.Sprintf("%d critical", c.Critical)),
		p.red(fmt.Sprintf("%d high", c.High)),
		p.yellow(fmt.Sprintf("%d medium", c.Medium)),
		fmt.Sprintf("%d low", c.Low),
		p.dim(fmt.Sprintf("%d negligible", c.Negligible)),
		p.dim(fmt.Sprintf("%d unknown", c.Unknown)),
	}
	return strings.Join(parts, "  ") + p.dim(fmt.Sprintf("   (%d total)", c.Total()))
}

// renderDeploymentTable prints one row per deployed instance. Each severity
// cell shows the deployed count and, in parentheses, the delta vs the new
// scan: positive (regression) in red, negative (improvement) in green.
func renderDeploymentTable(w io.Writer, p palette, ds []enrich.Comparison) {
	var head strings.Builder
	head.WriteString("  ")
	for _, c := range tableColumns {
		fmt.Fprintf(&head, "%-*s", c.width, c.head)
	}
	fmt.Fprintln(w, p.dim(head.String()))

	for _, d := range ds {
		dep := d.Deployed
		cells := []string{
			pad(truncate(dep.AccountID, tableColumns[0].width-1), tableColumns[0].width),
			pad(shortDigest(dep.Digest), tableColumns[1].width),
			pad(truncate(emptyDash(dep.Distro), tableColumns[2].width-1), tableColumns[2].width),
			p.eolStatus(pad(emptyDash(dep.DistroEOLStatus), tableColumns[3].width)),
			deltaCell(p, tableColumns[4].width, dep.CriticalCount, d.Delta.Critical),
			deltaCell(p, tableColumns[5].width, dep.HighCount, d.Delta.High),
			deltaCell(p, tableColumns[6].width, dep.MediumCount, d.Delta.Medium),
			deltaCell(p, tableColumns[7].width, dep.LowCount, d.Delta.Low),
			p.verdict(d.Verdict),
		}
		fmt.Fprintln(w, "  "+strings.Join(cells, ""))
	}
}

func pad(s string, width int) string {
	return fmt.Sprintf("%-*s", width, s)
}

const maxWorkloadsShown = 8

// renderPlacement prints, per deployed digest, the clusters / namespaces /
// workloads the image is actually running in.
func renderPlacement(w io.Writer, p palette, ds []enrich.Comparison) {
	hasAny := false
	for _, d := range ds {
		if d.Deployed.Placement != nil {
			hasAny = true
			break
		}
	}
	if !hasAny {
		return
	}

	fmt.Fprintf(w, "  %s\n\n", p.bold("Placement — where this image runs"))
	for _, d := range ds {
		dep := d.Deployed
		pl := dep.Placement
		if pl == nil {
			continue
		}
		fmt.Fprintf(w, "    %s  %s\n",
			p.cyan(shortDigest(dep.Digest)),
			p.dim(fmt.Sprintf("%d container(s) · %d cluster(s) · %d namespace(s)",
				pl.ContainerCount, pl.ClusterCount, len(pl.Namespaces))))
		if len(pl.Clusters) > 0 {
			fmt.Fprintf(w, "      %s %s\n", p.dim("clusters:  "), strings.Join(pl.Clusters, ", "))
		}
		if len(pl.Namespaces) > 0 {
			fmt.Fprintf(w, "      %s %s\n", p.dim("namespaces:"), strings.Join(pl.Namespaces, ", "))
		}
		if len(pl.Workloads) > 0 {
			fmt.Fprintf(w, "      %s %s\n", p.dim("workloads: "), workloadSummary(pl.Workloads))
		}
		fmt.Fprintln(w)
	}
}

func workloadSummary(ws []rad.Workload) string {
	parts := make([]string, 0, maxWorkloadsShown+1)
	for i, wl := range ws {
		if i >= maxWorkloadsShown {
			parts = append(parts, fmt.Sprintf("(+%d more)", len(ws)-maxWorkloadsShown))
			break
		}
		kind := wl.Kind
		if kind == "" {
			kind = "?"
		}
		parts = append(parts, kind+"/"+wl.Name)
	}
	return strings.Join(parts, ", ")
}

// deltaCell renders "<deployed> (<+/-delta>)" padded to width and colored by
// the direction of the delta.
func deltaCell(p palette, width, deployed, delta int) string {
	var text string
	if delta == 0 {
		text = fmt.Sprintf("%d", deployed)
	} else {
		text = fmt.Sprintf("%d (%+d)", deployed, delta)
	}
	padded := pad(text, width)
	switch {
	case delta > 0:
		return p.red(padded)
	case delta < 0:
		return p.green(padded)
	default:
		return p.dim(padded)
	}
}

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
