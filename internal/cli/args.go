package cli

import (
	"fmt"
	"strings"
)

// radFlags holds the values parsed out of argv for our --rad-* flags.
// All grype-bound args are returned untouched in passThrough.
type radFlags struct {
	report            string
	annotateSarif     bool
	failOnRegression  string
	failOnEol         bool
	grypeVersion      string
	accountIDsCSV     string // overrides env if set
	apiURL            string // overrides env if set
	imageNameOverride string
	imageRepoOverride string
	skipRAD           bool // explicit opt-out even if env is set
	grypeHelp         bool // print raw Grype help and exit
}

// extractRadFlags scans argv, plucking out --rad-* flags. Everything else is
// returned in the same relative order so it can be forwarded to grype.
func extractRadFlags(argv []string) (radFlags, []string, error) {
	var rf radFlags
	var pass []string

	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if !strings.HasPrefix(a, "--rad-") {
			pass = append(pass, a)
			continue
		}
		key, val, hasEq := strings.Cut(a, "=")
		take := func() (string, error) {
			if hasEq {
				return val, nil
			}
			if i+1 >= len(argv) {
				return "", fmt.Errorf("flag %s requires a value", key)
			}
			i++
			return argv[i], nil
		}
		var err error
		switch key {
		case "--rad-report":
			rf.report, err = take()
		case "--rad-annotate-sarif":
			if hasEq {
				rf.annotateSarif = val == "true" || val == "1"
			} else {
				rf.annotateSarif = true
			}
		case "--rad-fail-on-regression":
			rf.failOnRegression, err = take()
		case "--rad-fail-on-eol":
			if hasEq {
				rf.failOnEol = val == "true" || val == "1"
			} else {
				rf.failOnEol = true
			}
		case "--rad-grype-version":
			rf.grypeVersion, err = take()
		case "--rad-account-ids":
			rf.accountIDsCSV, err = take()
		case "--rad-api-url":
			rf.apiURL, err = take()
		case "--rad-image-name":
			rf.imageNameOverride, err = take()
		case "--rad-image-repo":
			rf.imageRepoOverride, err = take()
		case "--rad-skip":
			rf.skipRAD = true
		case "--rad-grype-help":
			rf.grypeHelp = true
		default:
			return rf, nil, fmt.Errorf("unknown rad flag: %s", key)
		}
		if err != nil {
			return rf, nil, err
		}
	}
	return rf, pass, nil
}

// hasOutputFlag reports whether argv contains a grype -o/--output flag. We
// use this to decide whether to add grype's default table output: in RAD
// mode we always inject `-o json=<tempfile>`, and grype suppresses its
// default stdout table once any -o is present, so without this check the
// user would see no terminal output at all.
func hasOutputFlag(argv []string) bool {
	for _, a := range argv {
		if a == "-o" || a == "--output" {
			return true
		}
	}
	return false
}

// findTarget returns the last positional argument in argv, which we treat as
// the scan target (image ref or sbom:path). It returns "" if every argv entry
// looks like a flag.
//
// This is heuristic but matches grype's invocation convention. Known
// value-taking flags (e.g. `-o`, `-c`, `-f`, `--file`, `--name`, `--scope`,
// `--platform`, `--config`, `--template`, `--output`, `--fail-on`,
// `--distro`, `--exclude`) consume the next argv entry so we don't mistake
// their value for the target.
func findTarget(argv []string) string {
	valueTaking := map[string]bool{
		"-o": true, "--output": true,
		"-c": true, "--config": true,
		"-t": true, "--template": true,
		"-f": true, "--fail-on": true,
		"--file":     true,
		"--name":     true,
		"--scope":    true,
		"--platform": true,
		"--distro":   true,
		"--exclude":  true,
	}
	last := ""
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if strings.HasPrefix(a, "-") {
			if valueTaking[a] && i+1 < len(argv) {
				i++
			}
			continue
		}
		last = a
	}
	return last
}
