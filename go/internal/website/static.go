package website

import (
	"context"
	"fmt"
	"io/fs"
	"math"
	"net/http"
	"sort"
	"strings"
)

// EcosystemDisplay holds pre-calculated bubble data for ecosystem vulnerability counts on the home page.
type EcosystemDisplay struct {
	Name       string
	Count      int
	Radius     float64
	TooltipTop float64
}

// HomePageData represents the data context passed to home.html template.
type HomePageData struct {
	ActiveSection     string
	DisableTurboCache bool
	Ecosystems        []EcosystemDisplay
}

func computeEcosystemDisplays(counts map[string]int) []EcosystemDisplay {
	var total int
	for _, c := range counts {
		total += c
	}
	if total == 0 {
		return nil
	}

	totalLog := math.Log(float64(total))
	displays := make([]EcosystemDisplay, 0, len(counts))
	for eco, count := range counts {
		if count <= 30 {
			continue
		}
		radius := math.Max((math.Log(float64(count))/totalLog)*100, 30)
		tooltipTop := -((radius / 2) + 5)
		displays = append(displays, EcosystemDisplay{
			Name:       eco,
			Count:      count,
			Radius:     radius,
			TooltipTop: tooltipTop,
		})
	}
	sort.Slice(displays, func(i, j int) bool {
		return strings.ToLower(displays[i].Name) < strings.ToLower(displays[j].Name)
	})

	return displays
}

func (s *Server) getEcosystemCounts(_ context.Context) map[string]int {
	// Stub for ecosystem count fetch (Datastore or cache integration)
	return map[string]int{
		"PyPI": 23174,
		"npm":  222222,
		"Go":   8010,
		"GIT":  943411,
		"Pub":  11,
	}
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("go-get") == "1" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(goVanityMetadata))

		return
	}

	data := HomePageData{
		ActiveSection:     "home",
		DisableTurboCache: false,
		Ecosystems:        computeEcosystemDisplays(s.getEcosystemCounts(r.Context())),
	}

	s.render(w, r, "home.html", http.StatusOK, data)
}

func (s *Server) handleGoBindingsVanity(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("go-get") == "1" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(goVanityMetadata))

		return
	}
	http.Redirect(w, r, "https://pkg.go.dev/osv.dev/bindings/go", http.StatusFound)
}

func (s *Server) handleSwagger(w http.ResponseWriter, r *http.Request) {
	http.ServeFileFS(w, r, s.config.DocsFS, "osv_service_v1.swagger.json")
}

func (s *Server) handlePublicKeys(w http.ResponseWriter, r *http.Request) {
	keyPath := "public_keys/" + r.PathValue("filename")
	if !fs.ValidPath(keyPath) {
		http.Error(w, "Invalid file path", http.StatusBadRequest)

		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	http.ServeFileFS(w, r, s.config.StaticFS, keyPath)
}

func (s *Server) handleFavicon(w http.ResponseWriter, r *http.Request) {
	http.ServeFileFS(w, r, s.config.StaticFS, "static/img/favicon-32x32.png")
}

func (s *Server) handleRobots(w http.ResponseWriter, r *http.Request) {
	if _, err := fs.Stat(s.config.StaticFS, "robots.txt"); err == nil {
		http.ServeFileFS(w, r, s.config.StaticFS, "robots.txt")

		return
	}
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	sitemapURL := fmt.Sprintf("%s://%s/sitemap_index.xml", scheme, r.Host)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprintf(w, "Sitemap: %s\n", sitemapURL)
}

func (s *Server) handleRedirect(targetURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetURL, http.StatusFound)
	}
}
