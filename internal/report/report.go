package report

import (
	"time"

	"github.com/rad-security/image-scanner/internal/enrich"
	"github.com/rad-security/image-scanner/internal/imageref"
)

// Report is the canonical RAD enrichment document.
// It is emitted standalone (via --rad-report path.json) and is also embedded
// into annotated SARIF as properties.rad on each run.
type Report struct {
	SchemaVersion string            `json:"schema_version"`
	GeneratedAt   time.Time         `json:"generated_at"`
	Image         ImageBlock        `json:"image"`
	GrypeSummary  GrypeSummaryBlock `json:"grype_summary"`
	RAD           *RADBlock         `json:"rad,omitempty"`
}

type ImageBlock struct {
	Input  string `json:"input"`
	Repo   string `json:"repo,omitempty"`
	Name   string `json:"name"`
	Tag    string `json:"tag,omitempty"`
	Digest string `json:"digest,omitempty"`
}

type GrypeSummaryBlock struct {
	GrypeVersion string            `json:"grype_version,omitempty"`
	Counts       enrich.Counts     `json:"counts"`
	DistroEOL    *enrich.DistroEOL `json:"distro_eol,omitempty"`
}

type RADBlock struct {
	AccountIDs     []string            `json:"account_ids"`
	Deployments    []enrich.Comparison `json:"deployments"`
	OverallVerdict enrich.Verdict      `json:"overall_verdict"`
}

// FromRef seeds a Report's image block from a parsed reference.
func FromRef(ref imageref.Ref) ImageBlock {
	return ImageBlock{
		Input:  ref.Full,
		Repo:   ref.Repo,
		Name:   ref.Name,
		Tag:    ref.Tag,
		Digest: ref.Digest,
	}
}

// OverallVerdict reduces per-deployment verdicts to a single value. If any
// deployment regresses, the overall verdict is regression. Otherwise mixed,
// improvement, unchanged (in that order of precedence).
func OverallVerdict(cs []enrich.Comparison) enrich.Verdict {
	if len(cs) == 0 {
		return enrich.VerdictUnchanged
	}
	seenImp, seenReg, seenMixed := false, false, false
	for _, c := range cs {
		switch c.Verdict {
		case enrich.VerdictRegression:
			seenReg = true
		case enrich.VerdictImprovement:
			seenImp = true
		case enrich.VerdictMixed:
			seenMixed = true
		}
	}
	switch {
	case seenReg:
		return enrich.VerdictRegression
	case seenMixed:
		return enrich.VerdictMixed
	case seenImp:
		return enrich.VerdictImprovement
	default:
		return enrich.VerdictUnchanged
	}
}
