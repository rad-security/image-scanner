package imageref

import "testing"

func TestParse(t *testing.T) {
	const digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	cases := []struct {
		in          string
		repo, name  string
		tag, digest string
	}{
		{"nginx:stable-alpine3.21", "docker.io/library/", "nginx", "stable-alpine3.21", ""},
		{"nginx", "docker.io/library/", "nginx", "", ""},
		{"library/nginx", "docker.io/library/", "nginx", "", ""},
		{"docker.io/library/nginx:1.27", "docker.io/library/", "nginx", "1.27", ""},
		{"docker:nginx:1.27", "docker.io/library/", "nginx", "1.27", ""},
		{"ghcr.io/example/svc:v1.2.3", "ghcr.io/example/", "svc", "v1.2.3", ""},
		{
			"259733667621.dkr.ecr.us-east-1.amazonaws.com/dependencies/registry.k8s.io/capi-operator/cluster-api-operator:v0.23.0",
			"259733667621.dkr.ecr.us-east-1.amazonaws.com/dependencies/registry.k8s.io/capi-operator/",
			"cluster-api-operator", "v0.23.0", "",
		},
		{
			"registry.example.com:5000/foo/bar@" + digest,
			"registry.example.com:5000/foo/", "bar", "", digest,
		},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if err != nil {
			t.Errorf("Parse(%q) error: %v", c.in, err)
			continue
		}
		if got.Repo != c.repo || got.Name != c.name || got.Tag != c.tag || got.Digest != c.digest {
			t.Errorf("Parse(%q):\n  got  repo=%q name=%q tag=%q digest=%q\n  want repo=%q name=%q tag=%q digest=%q",
				c.in, got.Repo, got.Name, got.Tag, got.Digest, c.repo, c.name, c.tag, c.digest)
		}
	}
}

func TestParseEmpty(t *testing.T) {
	if _, err := Parse(""); err == nil {
		t.Errorf("expected error for empty input")
	}
}

func TestParseInvalid(t *testing.T) {
	if _, err := Parse("NOT A VALID REF!!"); err == nil {
		t.Errorf("expected error for invalid reference")
	}
}
