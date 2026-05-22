package enrich

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Counts is the severity histogram we compute from grype's JSON output and
// compare against the corresponding fields in the RAD inventory record.
type Counts struct {
	Critical   int `json:"critical"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	Negligible int `json:"negligible"`
	Unknown    int `json:"unknown"`
}

func (c Counts) Total() int {
	return c.Critical + c.High + c.Medium + c.Low + c.Negligible + c.Unknown
}

// DistroEOL describes the end-of-life distro the *scanned* image is built on.
// It is non-nil only when grype emits a distro-eol alert.
type DistroEOL struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Message string `json:"message"`
}

func (d DistroEOL) Distro() string {
	if d.Version == "" {
		return d.Name
	}
	return d.Name + " " + d.Version
}

// GrypeScan is everything we extract from a single grype JSON document.
type GrypeScan struct {
	Counts    Counts
	DistroEOL *DistroEOL
}

// grypeDoc is the minimal slice of grype's JSON we need.
type grypeDoc struct {
	Matches []struct {
		Vulnerability struct {
			Severity string `json:"severity"`
		} `json:"vulnerability"`
	} `json:"matches"`
	AlertsByPackage []struct {
		Alerts []struct {
			Type     string `json:"type"`
			Message  string `json:"message"`
			Metadata struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"metadata"`
		} `json:"alerts"`
	} `json:"alertsByPackage"`
}

// ParseGrypeScan reads a grype JSON document and returns the severity
// histogram plus, if present, the end-of-life distro of the scanned image.
//
// Severity values in grype output are mixed-case ("Critical", "High", ...);
// we normalise via lowercase comparison.
func ParseGrypeScan(r io.Reader) (GrypeScan, error) {
	var doc grypeDoc
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return GrypeScan{}, fmt.Errorf("parsing grype json: %w", err)
	}

	var out GrypeScan
	for _, m := range doc.Matches {
		switch strings.ToLower(m.Vulnerability.Severity) {
		case "critical":
			out.Counts.Critical++
		case "high":
			out.Counts.High++
		case "medium":
			out.Counts.Medium++
		case "low":
			out.Counts.Low++
		case "negligible":
			out.Counts.Negligible++
		default:
			out.Counts.Unknown++
		}
	}

	for _, pkg := range doc.AlertsByPackage {
		for _, a := range pkg.Alerts {
			if a.Type == "distro-eol" {
				out.DistroEOL = &DistroEOL{
					Name:    a.Metadata.Name,
					Version: a.Metadata.Version,
					Message: a.Message,
				}
				return out, nil // one is enough; the distro is image-wide
			}
		}
	}
	return out, nil
}
