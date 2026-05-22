package enrich

import (
	"fmt"
	"strings"

	"github.com/rad-security/image-scanner/internal/rad"
)

// Verdict categorises a count-based comparison.
type Verdict string

const (
	VerdictImprovement Verdict = "improvement"
	VerdictRegression  Verdict = "regression"
	VerdictMixed       Verdict = "mixed"
	VerdictUnchanged   Verdict = "unchanged"
)

// SeverityFloor names the lowest severity that should be considered when
// deciding whether a delta represents a regression.
type SeverityFloor string

const (
	FloorCritical SeverityFloor = "critical"
	FloorHigh     SeverityFloor = "high"
	FloorMedium   SeverityFloor = "medium"
	FloorLow      SeverityFloor = "low"
	FloorAny      SeverityFloor = "any"
)

func ParseSeverityFloor(s string) (SeverityFloor, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return "", nil
	case "critical":
		return FloorCritical, nil
	case "high":
		return FloorHigh, nil
	case "medium":
		return FloorMedium, nil
	case "low":
		return FloorLow, nil
	case "any":
		return FloorAny, nil
	default:
		return "", fmt.Errorf("invalid severity %q (want critical|high|medium|low|any)", s)
	}
}

// Delta is signed counts: positive == regression for that severity.
type Delta struct {
	Critical   int `json:"critical"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	Negligible int `json:"negligible"`
}

// Comparison pairs one deployed instance with the delta vs the freshly-
// scanned image and a coarse verdict.
type Comparison struct {
	Deployed rad.DeployedImage `json:"deployed"`
	Delta    Delta             `json:"delta_vs_new_scan"`
	Verdict  Verdict           `json:"verdict"`
}

// CompareAll returns one Comparison per deployed instance.
func CompareAll(scan Counts, deployed []rad.DeployedImage) []Comparison {
	out := make([]Comparison, 0, len(deployed))
	for _, d := range deployed {
		delta := Delta{
			Critical:   scan.Critical - d.CriticalCount,
			High:       scan.High - d.HighCount,
			Medium:     scan.Medium - d.MediumCount,
			Low:        scan.Low - d.LowCount,
			Negligible: scan.Negligible - d.NegligibleCount,
		}
		out = append(out, Comparison{
			Deployed: d,
			Delta:    delta,
			Verdict:  verdictOf(delta),
		})
	}
	return out
}

func verdictOf(d Delta) Verdict {
	pos := d.Critical > 0 || d.High > 0 || d.Medium > 0 || d.Low > 0 || d.Negligible > 0
	neg := d.Critical < 0 || d.High < 0 || d.Medium < 0 || d.Low < 0 || d.Negligible < 0
	switch {
	case pos && neg:
		return VerdictMixed
	case pos:
		return VerdictRegression
	case neg:
		return VerdictImprovement
	default:
		return VerdictUnchanged
	}
}

// RegressionAt reports whether any comparison shows a positive delta at the
// given severity floor or above. Returns the offending comparison index for
// reporting.
func RegressionAt(comparisons []Comparison, floor SeverityFloor) (bool, int) {
	for i, c := range comparisons {
		if regressionMatches(c.Delta, floor) {
			return true, i
		}
	}
	return false, -1
}

func regressionMatches(d Delta, floor SeverityFloor) bool {
	switch floor {
	case FloorCritical:
		return d.Critical > 0
	case FloorHigh:
		return d.Critical > 0 || d.High > 0
	case FloorMedium:
		return d.Critical > 0 || d.High > 0 || d.Medium > 0
	case FloorLow:
		return d.Critical > 0 || d.High > 0 || d.Medium > 0 || d.Low > 0
	case FloorAny:
		return d.Critical > 0 || d.High > 0 || d.Medium > 0 || d.Low > 0 || d.Negligible > 0
	}
	return false
}
