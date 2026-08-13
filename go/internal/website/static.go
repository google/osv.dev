package website

import (
	"context"
	"fmt"
	"io/fs"
	"math"
	"net/http"
	"sort"
	"strings"

	"github.com/google/osv.dev/go/logger"
)

// RenderNotFound renders the standard 404 Not Found page.
func (s *Server) RenderNotFound(w http.ResponseWriter, r *http.Request) {
	s.RenderNotFoundWithVuln(w, r, "")
}

// RenderNotFoundWithVuln renders the 404 Not Found page with a failed import vulnerability ID.
func (s *Server) RenderNotFoundWithVuln(w http.ResponseWriter, r *http.Request, failedImportVulnID string) {
	data := NotFoundPageData{
		BasePageData: BasePageData{
			ActiveSection:     "",
			DisableTurboCache: false,
		},
		FailedImportVulnID: failedImportVulnID,
	}

	s.render(w, r, "404.html", http.StatusNotFound, data)
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

func (s *Server) getEcosystemCounts(ctx context.Context) map[string]int {
	res, err := s.stores.VulnSearch.EcosystemCounts(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "failed to get ecosystem counts", "error", err)

		return map[string]int{}
	}

	counts := make(map[string]int, len(res))
	for _, eco := range res {
		counts[eco.Name] = eco.Count
	}

	return counts
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("go-get") == "1" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(goVanityMetadata))

		return
	}

	data := HomePageData{
		BasePageData: BasePageData{
			ActiveSection:     "home",
			DisableTurboCache: false,
		},
		Ecosystems: computeEcosystemDisplays(s.getEcosystemCounts(r.Context())),
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
