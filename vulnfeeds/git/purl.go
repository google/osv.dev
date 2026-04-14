package git

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
)

// BuildGenericRepoPURL returns an unversioned generic purl for a repo URL.
// Example: pkg:generic/github.com/owner/repo
func BuildGenericRepoPURL(repoURL string) (string, error) {
	p, err := ParseRepoPURL(repoURL)
	if err != nil {
		return "", err
	}

	return p.ToString(), nil
}

// ParseRepoPURL decodes a repo URL into a PackageURL template with type,
// namespace, and name populated. packageurl-go handles version
// escaping so reserved characters such as "/" are encoded to "%2F".
func ParseRepoPURL(repoURL string) (*packageurl.PackageURL, error) {
	u, err := url.Parse(normalizeRepoURL(repoURL))
	if err != nil {
		return nil, fmt.Errorf("invalid repo url: %w", err)
	}

	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return nil, fmt.Errorf("unsupported scheme %q in %q", u.Scheme, repoURL)
	}

	host := strings.ToLower(u.Hostname())
	if host == "" {
		return nil, fmt.Errorf("missing host in %q", repoURL)
	}

	path := strings.Trim(strings.TrimSuffix(u.Path, ".git"), "/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] == "" {
		return nil, fmt.Errorf("invalid repo path in %q", repoURL)
	}

	return packageurl.NewPackageURL(
		"generic",
		strings.Join(append([]string{host}, parts[:len(parts)-1]...), "/"),
		parts[len(parts)-1],
		"", nil, "",
	), nil
}

// normalizeRepoURL rewrites common git-transport variants into an https URL
// so ParseRepoPURL can treat them uniformly.
// Inputs with an unrecognized scheme (ftp://, file://, …) are returned as-is
// so ParseRepoPURL can reject them via its scheme check.
func normalizeRepoURL(raw string) string {
	raw = strings.TrimSpace(raw)

	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return raw
	}

	body := raw
	hadScheme := false
	if i := strings.Index(body, "://"); i != -1 {
		scheme := strings.ToLower(body[:i])
		if scheme != "git" && scheme != "ssh" {
			return raw
		}
		body = body[i+3:]
		hadScheme = true
	}

	if at := strings.Index(body, "@"); at != -1 {
		if slash := strings.Index(body, "/"); slash == -1 || at < slash {
			body = body[at+1:]
		}
	}

	if colon := strings.Index(body, ":"); colon != -1 {
		slash := strings.Index(body, "/")
		if slash == -1 || colon < slash {
			portEnd := slash
			if portEnd == -1 {
				portEnd = len(body)
			}
			if _, err := strconv.Atoi(body[colon+1 : portEnd]); err != nil {
				body = body[:colon] + "/" + body[colon+1:]
			}
		}
	}

	if hadScheme || body != raw {
		return "https://" + body
	}

	return raw
}
