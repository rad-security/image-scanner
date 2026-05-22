package imageref

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// FromTarget resolves a scan target string into a parsed image Ref.
//
// Supports:
//   - "image-ref"              → parse as a registry reference
//   - "sbom:./file.json"       → extract userInput from Syft SBOM source metadata
//   - "./file.json"            → treated as SBOM file if it exists and looks like one
//
// If the target is an SBOM, the source metadata MUST point at an image
// reference. If the SBOM was generated from a directory or filesystem, RAD
// enrichment cannot be performed and the caller should treat this as an error
// when RAD is enabled.
func FromTarget(target string) (Ref, error) {
	if path, ok := strings.CutPrefix(target, "sbom:"); ok {
		return fromSBOM(path)
	}
	return Parse(target)
}

// syftSource captures the bits of a Syft JSON SBOM that we need. Syft has
// shipped two layouts over time, so we try both.
type syftSource struct {
	Type     string `json:"type"`
	Metadata struct {
		UserInput string `json:"userInput"`
	} `json:"metadata"`
	Target struct {
		UserInput string `json:"userInput"`
	} `json:"target"`
}

type syftSBOM struct {
	Source syftSource `json:"source"`
}

func fromSBOM(path string) (Ref, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Ref{}, fmt.Errorf("reading sbom %s: %w", path, err)
	}
	var s syftSBOM
	if err := json.Unmarshal(data, &s); err != nil {
		return Ref{}, fmt.Errorf("parsing sbom %s: %w", path, err)
	}

	input := s.Source.Target.UserInput
	if input == "" {
		input = s.Source.Metadata.UserInput
	}
	if input == "" {
		return Ref{}, fmt.Errorf("sbom %s has no source.userInput — cannot derive image name", path)
	}
	if s.Source.Type != "" && s.Source.Type != "image" {
		return Ref{}, fmt.Errorf("sbom %s is not from an image (type=%q) — RAD enrichment requires an image source", path, s.Source.Type)
	}
	return Parse(input)
}
