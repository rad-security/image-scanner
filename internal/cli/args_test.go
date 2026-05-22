package cli

import (
	"reflect"
	"testing"
)

func TestExtractRadFlags(t *testing.T) {
	argv := []string{
		"--add-cpes-if-none",
		"-o", "sarif",
		"--file", "out.sarif",
		"--rad-report=./rep.json",
		"--rad-fail-on-regression", "critical",
		"--rad-annotate-sarif",
		"alpine:3.18",
	}
	rf, pass, err := extractRadFlags(argv)
	if err != nil {
		t.Fatal(err)
	}
	if rf.report != "./rep.json" || rf.failOnRegression != "critical" || !rf.annotateSarif {
		t.Errorf("rad flags: %+v", rf)
	}
	want := []string{"--add-cpes-if-none", "-o", "sarif", "--file", "out.sarif", "alpine:3.18"}
	if !reflect.DeepEqual(pass, want) {
		t.Errorf("passthrough mismatch\n  got:  %v\n  want: %v", pass, want)
	}
}

func TestFindTarget(t *testing.T) {
	cases := []struct {
		argv []string
		want string
	}{
		{[]string{"alpine:3.18"}, "alpine:3.18"},
		{[]string{"-o", "sarif", "--file", "out.sarif", "alpine:3.18"}, "alpine:3.18"},
		{[]string{"--add-cpes-if-none", "-c", "config.yaml", "sbom:./sbom.json"}, "sbom:./sbom.json"},
		{[]string{"--fail-on", "high", "registry.example.com/foo/bar:v1"}, "registry.example.com/foo/bar:v1"},
	}
	for _, c := range cases {
		got := findTarget(c.argv)
		if got != c.want {
			t.Errorf("findTarget(%v) = %q want %q", c.argv, got, c.want)
		}
	}
}

func TestHasOutputFlag(t *testing.T) {
	cases := []struct {
		argv []string
		want bool
	}{
		{[]string{"nginx:stable-alpine3.21"}, false},
		{[]string{"-o", "sarif", "nginx"}, true},
		{[]string{"--output", "json", "nginx"}, true},
		{[]string{"--add-cpes-if-none", "nginx"}, false},
	}
	for _, c := range cases {
		if got := hasOutputFlag(c.argv); got != c.want {
			t.Errorf("hasOutputFlag(%v) = %v want %v", c.argv, got, c.want)
		}
	}
}

func TestFindSarifOutput(t *testing.T) {
	cases := []struct {
		argv []string
		want string
	}{
		{[]string{"-o", "sarif=out.sarif", "alpine"}, "out.sarif"},
		{[]string{"-o", "sarif", "--file", "out.sarif", "alpine"}, "out.sarif"},
		{[]string{"--output", "sarif=x.sarif", "alpine"}, "x.sarif"},
		{[]string{"-o", "table", "alpine"}, ""},
		{[]string{"-o", "sarif", "alpine"}, ""}, // stdout SARIF, can't annotate
	}
	for _, c := range cases {
		got := findSarifOutput(c.argv)
		if got != c.want {
			t.Errorf("findSarifOutput(%v) = %q want %q", c.argv, got, c.want)
		}
	}
}
