package report

import (
	"encoding/json"
	"fmt"
	"os"
)

// AnnotateSARIF reads the SARIF document at path, injects this report under
// runs[].properties.rad on every run, and writes the result back to the same
// path. SARIF consumers that don't recognise the property simply ignore it.
func AnnotateSARIF(path string, r Report) error {
	r.SchemaVersion = SchemaVersion

	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading sarif %s: %w", path, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("parsing sarif %s: %w", path, err)
	}

	runs, ok := doc["runs"].([]any)
	if !ok {
		return fmt.Errorf("sarif %s has no runs array", path)
	}
	for i, runAny := range runs {
		run, ok := runAny.(map[string]any)
		if !ok {
			continue
		}
		props, _ := run["properties"].(map[string]any)
		if props == nil {
			props = map[string]any{}
		}
		props["rad"] = r
		run["properties"] = props
		runs[i] = run
	}
	doc["runs"] = runs

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling sarif: %w", err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return fmt.Errorf("writing sarif %s: %w", path, err)
	}
	return nil
}
