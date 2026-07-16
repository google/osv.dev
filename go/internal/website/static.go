package website

import (
	"fmt"
	"io/fs"
	"net/http"
)

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("go-get") == "1" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(goVanityMetadata))

		return
	}
	http.ServeFileFS(w, r, s.config.StaticFS, "home.html")
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
