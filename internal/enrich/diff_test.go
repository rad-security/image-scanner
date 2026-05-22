package enrich

import (
	"strings"
	"testing"

	"github.com/rad-security/image-scanner/internal/rad"
)

func TestParseGrypeScanCounts(t *testing.T) {
	doc := `{"matches":[
		{"vulnerability":{"severity":"Critical"}},
		{"vulnerability":{"severity":"high"}},
		{"vulnerability":{"severity":"High"}},
		{"vulnerability":{"severity":"Medium"}},
		{"vulnerability":{"severity":"Low"}},
		{"vulnerability":{"severity":"Negligible"}},
		{"vulnerability":{"severity":"Unknown"}}
	]}`
	got, err := ParseGrypeScan(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	want := Counts{Critical: 1, High: 2, Medium: 1, Low: 1, Negligible: 1, Unknown: 1}
	if got.Counts != want {
		t.Errorf("got %+v want %+v", got.Counts, want)
	}
	if got.DistroEOL != nil {
		t.Errorf("expected no distro EOL, got %+v", got.DistroEOL)
	}
}

func TestParseGrypeScanDistroEOL(t *testing.T) {
	doc := `{"matches":[],"alertsByPackage":[
		{"alerts":[
			{"type":"distro-eol","message":"Package is from end-of-life distro: alpine 3.18.12",
			 "metadata":{"name":"alpine","version":"3.18.12"}}
		]}
	]}`
	got, err := ParseGrypeScan(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if got.DistroEOL == nil {
		t.Fatal("expected a distro EOL alert")
	}
	if got.DistroEOL.Distro() != "alpine 3.18.12" {
		t.Errorf("got distro %q, want %q", got.DistroEOL.Distro(), "alpine 3.18.12")
	}
}

func TestCompareAndVerdict(t *testing.T) {
	scan := Counts{Critical: 5, High: 20}
	deployed := []rad.DeployedImage{
		{CriticalCount: 3, HighCount: 24}, // delta +2C/-4H → mixed
		{CriticalCount: 5, HighCount: 20}, // unchanged
		{CriticalCount: 6, HighCount: 25}, // delta -1C/-5H → improvement
		{CriticalCount: 2, HighCount: 10}, // delta +3C/+10H → regression
	}
	cs := CompareAll(scan, deployed)
	got := []Verdict{cs[0].Verdict, cs[1].Verdict, cs[2].Verdict, cs[3].Verdict}
	want := []Verdict{VerdictMixed, VerdictUnchanged, VerdictImprovement, VerdictRegression}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("idx %d: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestRegressionAt(t *testing.T) {
	cs := []Comparison{{Delta: Delta{Critical: 0, High: 2}}}
	if hit, _ := RegressionAt(cs, FloorCritical); hit {
		t.Errorf("critical floor should not trigger on high-only regression")
	}
	if hit, _ := RegressionAt(cs, FloorHigh); !hit {
		t.Errorf("high floor should trigger on high regression")
	}
}
