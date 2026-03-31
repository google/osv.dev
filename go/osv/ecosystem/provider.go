package ecosystem

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvconstants"
)

// Provider is the dependency container for ecosystems.
type Provider struct {
	Client *http.Client
}

func NewProvider(client *http.Client) *Provider {
	return &Provider{
		Client: client,
	}
}

var DefaultProvider = NewProvider(http.DefaultClient)

// Get returns an ecosystem for the given ecosystem name.
// If the ecosystem is not found, it returns nil, false.
func (p *Provider) Get(ecosystem string) (Ecosystem, bool) {
	name, suffix, _ := strings.Cut(ecosystem, ":")
	f, ok := ecosystems[osvconstants.Ecosystem(name)]
	if !ok {
		return nil, false
	}
	e := f(p, suffix)
	if enum, ok := e.(Enumerable); ok {
		return &enumerableWrapper{Enumerable: enum}, true
	}

	return &ecosystemWrapper{Ecosystem: e}, true
}

// fetchJSON fetches a JSON payload from the given URL and decodes it into the provided target.
// It translates HTTP 404 into ErrPackageNotFound.
func (p *Provider) fetchJSON(urlStr string, target any) error {
	resp, err := p.Client.Get(urlStr)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ErrPackageNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %s", resp.Status)
	}

	return json.NewDecoder(resp.Body).Decode(target)
}

// getVersionsDepsDev enumerates versions for a package using the deps.dev API.
func (p *Provider) getVersionsDepsDev(e Ecosystem, depsDevSystem string, pkg string) ([]string, error) {
	urlStr := fmt.Sprintf("https://api.deps.dev/v3alpha/systems/%s/packages/%s",
		url.PathEscape(depsDevSystem),
		url.PathEscape(pkg),
	)

	var data struct {
		Versions []struct {
			VersionKey struct {
				Version string `json:"version"`
			} `json:"versionKey"`
		} `json:"versions"`
	}

	if err := p.fetchJSON(urlStr, &data); err != nil {
		return nil, fmt.Errorf("failed to get %s versions from deps.dev for %s: %w", depsDevSystem, pkg, err)
	}

	versions := make([]string, 0, len(data.Versions))
	for _, v := range data.Versions {
		versions = append(versions, v.VersionKey.Version)
	}

	return sortVersions(e, versions)
}
