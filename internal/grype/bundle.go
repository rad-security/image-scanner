package grype

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	releaseHost  = "https://github.com/anchore/grype/releases/download"
	downloadHTTP = 5 * time.Minute
)

// Locate returns a usable path to a grype binary matching the requested
// version. Resolution order:
//  1. $RAD_GRYPE_PATH — explicit override
//  2. grype in $PATH if its `--version` matches the requested version
//  3. $XDG_CACHE_HOME/rad-image-scanner/grype-<ver>/grype
//  4. Download from GitHub releases, verify SHA256, extract into the cache
func Locate(ctx context.Context, version string) (string, error) {
	if v := os.Getenv("RAD_GRYPE_PATH"); v != "" {
		if _, err := os.Stat(v); err == nil {
			return v, nil
		}
	}

	if p, err := exec.LookPath("grype"); err == nil {
		if pathVer, err := readBinaryVersion(ctx, p); err == nil && pathVer == version {
			return p, nil
		}
	}

	cacheDir, err := cacheDir(version)
	if err != nil {
		return "", err
	}
	cached := filepath.Join(cacheDir, "grype")
	if _, err := os.Stat(cached); err == nil {
		return cached, nil
	}

	if err := download(ctx, version, cacheDir); err != nil {
		return "", err
	}
	return cached, nil
}

func cacheDir(version string) (string, error) {
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolving home directory: %w", err)
		}
		base = filepath.Join(home, ".cache")
	}
	return filepath.Join(base, "rad-image-scanner", "grype-v"+version), nil
}

func readBinaryVersion(ctx context.Context, path string) (string, error) {
	out, err := exec.CommandContext(ctx, path, "version", "-o", "json").Output()
	if err != nil {
		return "", err
	}
	// Best-effort: search for the application field rather than full JSON
	// decode, since grype's output schema for `version` has shifted between
	// releases.
	const key = `"version":"`
	_, after, ok := strings.Cut(string(out), key)
	if !ok {
		return "", fmt.Errorf("could not parse grype version output")
	}
	before, _, ok := strings.Cut(after, `"`)
	if !ok {
		return "", fmt.Errorf("could not parse grype version output")
	}
	return before, nil
}

func download(ctx context.Context, version, destDir string) error {
	osName, arch, err := platform()
	if err != nil {
		return err
	}

	archive := fmt.Sprintf("grype_%s_%s_%s.tar.gz", version, osName, arch)
	archiveURL := fmt.Sprintf("%s/v%s/%s", releaseHost, version, archive)
	checksumsURL := fmt.Sprintf("%s/v%s/grype_%s_checksums.txt", releaseHost, version, version)

	expectedSHA, err := fetchExpectedSHA(ctx, checksumsURL, archive)
	if err != nil {
		return fmt.Errorf("fetching grype checksums: %w", err)
	}

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("creating cache dir: %w", err)
	}

	tarPath := filepath.Join(destDir, archive)
	if err := downloadToFile(ctx, archiveURL, tarPath); err != nil {
		return fmt.Errorf("downloading grype: %w", err)
	}
	defer os.Remove(tarPath)

	if err := verifySHA256(tarPath, expectedSHA); err != nil {
		return fmt.Errorf("verifying grype archive: %w", err)
	}

	if err := extractGrype(tarPath, destDir); err != nil {
		return fmt.Errorf("extracting grype: %w", err)
	}
	return nil
}

func platform() (osName, arch string, err error) {
	switch runtime.GOOS {
	case "linux", "darwin", "windows":
		osName = runtime.GOOS
	default:
		return "", "", fmt.Errorf("unsupported os: %s", runtime.GOOS)
	}
	switch runtime.GOARCH {
	case "amd64", "arm64":
		arch = runtime.GOARCH
	default:
		return "", "", fmt.Errorf("unsupported arch: %s", runtime.GOARCH)
	}
	return osName, arch, nil
}

func fetchExpectedSHA(ctx context.Context, url, archiveName string) (string, error) {
	client := &http.Client{Timeout: downloadHTTP}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d fetching checksums", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == archiveName {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("archive %s not found in checksums", archiveName)
}

func downloadToFile(ctx context.Context, url, dest string) error {
	client := &http.Client{Timeout: downloadHTTP}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}
	return nil
}

func verifySHA256(path, expected string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, expected) {
		return fmt.Errorf("checksum mismatch: got %s, want %s", got, expected)
	}
	return nil
}

func extractGrype(tarPath, destDir string) error {
	f, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		base := filepath.Base(hdr.Name)
		if base != "grype" && base != "grype.exe" {
			continue
		}
		dest := filepath.Join(destDir, base)
		out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return err
		}
		// Close is checked here: this is the binary we are about to execute,
		// so a failed flush (e.g. disk full) must not be silently ignored.
		if err := out.Close(); err != nil {
			return fmt.Errorf("finalizing grype binary: %w", err)
		}
		return nil
	}
	return fmt.Errorf("grype binary not found inside archive")
}
