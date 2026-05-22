package report

import (
	"encoding/json"
	"fmt"
	"os"
)

const SchemaVersion = "1"

// WriteJSON marshals the report as indented JSON to path.
func WriteJSON(path string, r Report) error {
	r.SchemaVersion = SchemaVersion
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling report: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing report to %s: %w", path, err)
	}
	return nil
}
