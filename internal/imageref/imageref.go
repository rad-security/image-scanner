package imageref

import (
	"fmt"
	"strings"

	"github.com/distribution/reference"
)

// Ref describes the parts of a container image reference that we need to
// query the RAD inventory.
//
//	Full:   the original input (without the sbom: prefix, if any)
//	Repo:   registry/path/ portion ending in a slash (matches RAD's "repo" field)
//	Name:   final path segment (matches RAD's "name" field)
//	Tag:    optional tag (after ':')
//	Digest: optional digest (after '@')
type Ref struct {
	Full   string
	Repo   string
	Name   string
	Tag    string
	Digest string
}

// grypeImageSchemes are the grype source-scheme prefixes that still resolve to
// a registry image reference. We strip them before normalising. Non-image
// schemes (dir:, file:, oci-dir:, ...) are not registry images, so RAD
// enrichment for those needs an explicit --rad-image-name/--rad-image-repo.
var grypeImageSchemes = []string{"docker:", "podman:", "registry:"}

// Parse extracts a Ref from a Docker image reference such as
//
//	nginx:stable-alpine3.21
//	library/nginx
//	registry.example.com/foo/bar/baz:v1
//	registry.example.com/foo/bar/baz@sha256:<digest>
//
// References are normalised the same way a container runtime would: a bare
// name like "nginx" becomes "docker.io/library/nginx", so Repo is
// "docker.io/library/" and Name is "nginx". This matches the fully-qualified
// "repo" values stored in the RAD inventory.
func Parse(ref string) (Ref, error) {
	if ref == "" {
		return Ref{}, fmt.Errorf("empty image reference")
	}

	cleaned := ref
	for _, scheme := range grypeImageSchemes {
		if rest, ok := strings.CutPrefix(cleaned, scheme); ok {
			cleaned = rest
			break
		}
	}

	named, err := reference.ParseNormalizedNamed(cleaned)
	if err != nil {
		return Ref{}, fmt.Errorf("parsing image reference %q: %w (use --rad-image-name/--rad-image-repo to override)", ref, err)
	}

	out := Ref{Full: ref}

	// domain + path is the fully-qualified name, e.g. "docker.io/library/nginx".
	fullPath := reference.Domain(named) + "/" + reference.Path(named)
	if i := strings.LastIndex(fullPath, "/"); i >= 0 {
		out.Repo = fullPath[:i+1] // keep trailing slash
		out.Name = fullPath[i+1:]
	} else {
		out.Name = fullPath
	}

	if tagged, ok := named.(reference.Tagged); ok {
		out.Tag = tagged.Tag()
	}
	if canonical, ok := named.(reference.Canonical); ok {
		out.Digest = canonical.Digest().String()
	}

	if out.Name == "" {
		return Ref{}, fmt.Errorf("could not extract image name from %q", ref)
	}
	return out, nil
}
