package ecosystem

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/tidwall/gjson"
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
	if e == nil {
		// Factory rejected this ecosystem (e.g. malformed TuxCare).
		return nil, false
	}
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

// fetchJSONPaths fetches JSON from the given URL and extracts strings from one or more GJSON paths.
// It flattens any arrays it finds into a single string slice.
// It translates HTTP 404 into ErrPackageNotFound.
// It uses gjson.GetBytes to scan the raw JSON bytes without fully decoding them into Go structs.
func (p *Provider) fetchJSONPaths(urlStr string, paths ...string) ([]string, error) {
	resp, err := p.Client.Get(urlStr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrPackageNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var results []string
	for _, path := range paths {
		res := gjson.GetBytes(body, path)
		if res.IsArray() {
			for _, v := range res.Array() {
				if v.String() != "" {
					results = append(results, v.String())
				}
			}
		} else if res.String() != "" {
			results = append(results, res.String())
		}
	}

	return results, nil
}

// getVersionsDepsDev enumerates versions for a package using the deps.dev API.
func (p *Provider) getVersionsDepsDev(e Ecosystem, depsDevSystem string, pkg string) ([]string, error) {
	urlStr := fmt.Sprintf("https://api.deps.dev/v3alpha/systems/%s/packages/%s",
		url.PathEscape(depsDevSystem),
		url.PathEscape(pkg),
	)

	versions, err := p.fetchJSONPaths(urlStr, "versions.#.versionKey.version")
	if err != nil {
		return nil, fmt.Errorf("failed to get %s versions from deps.dev for %s: %w", depsDevSystem, pkg, err)
	}

	return sortVersions(e, versions)
}
