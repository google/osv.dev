package git

import (
	"fmt"
	"net/url"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
)

// BuildGenericRepoPURL returns an unversioned generic purl for a repo URL.
// Example: pkg:generic/github.com/owner/repo
func BuildGenericRepoPURL(repoURL string) (string, error) {
	return buildGenericRepoPURL(repoURL, "")
}

// BuildVersionedGenericRepoPURL returns a generic purl whose version
// component is the given string, encoded by packageurl-go.
// A tag like "release/1.2.3" becomes "...@release%2F1.2.3" rather than a
// malformed "...@release/1.2.3".
// Example: pkg:generic/github.com/owner/repo@v1.0.0
func BuildVersionedGenericRepoPURL(repoURL, version string) (string, error) {
	return buildGenericRepoPURL(repoURL, version)
}

func buildGenericRepoPURL(repoURL, version string) (string, error) {
	u, err := url.Parse(repoURL)
	if err != nil {
		return "", fmt.Errorf("invalid repo url: %w", err)
	}

	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return "", fmt.Errorf("unsupported scheme %q in %q", u.Scheme, repoURL)
	}

	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", fmt.Errorf("missing host in %q", repoURL)
	}

	path := strings.Trim(strings.TrimSuffix(u.Path, ".git"), "/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] == "" {
		return "", fmt.Errorf("invalid repo path in %q", repoURL)
	}

	// Namespace is host + all path segments except the last; name is the last segment.
	ns := strings.Join(append([]string{host}, parts[:len(parts)-1]...), "/")
	name := parts[len(parts)-1]

	p := packageurl.NewPackageURL("generic", ns, name, version, nil, "")

	return p.ToString(), nil
}
