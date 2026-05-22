package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
)

func Execute() error {
	root := newRootCmd()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}
	return nil
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:                "rad-image-scanner [image|sbom:path] [grype-args...]",
		Short:              "Container image vulnerability scanner that wraps Grype with RAD Security enrichment",
		Long:               "rad-image-scanner runs Grype against a container image or SBOM and, when RAD Security credentials are present, enriches the report with currently-deployed image vulnerability counts, regression detection, and distro EOL information.",
		SilenceUsage:       true,
		SilenceErrors:      true,
		DisableFlagParsing: true,
		Args:               cobra.MinimumNArgs(1),
		RunE:               runScan,
		Version:            fmt.Sprintf("%s (commit %s)", version, commit),
	}
	return cmd
}
