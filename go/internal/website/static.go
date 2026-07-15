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
	if s.config.StaticFS != nil {
		if _, err := fs.Stat(s.config.StaticFS, "home.html"); err == nil {
			http.ServeFileFS(w, r, s.config.StaticFS, "home.html")

			return
		}
	}
	http.NotFound(w, r)
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
	if s.config.DocsFS != nil {
		filename := "osv_service_v1.swagger.json"
		if _, err := fs.Stat(s.config.DocsFS, filename); err == nil {
			http.ServeFileFS(w, r, s.config.DocsFS, filename)

			return
		}
	}
	http.NotFound(w, r)
}

func (s *Server) handlePublicKeys(w http.ResponseWriter, r *http.Request) {
	keyPath := "public_keys/" + r.PathValue("filename")
	if !fs.ValidPath(keyPath) {
		http.Error(w, "Invalid file path", http.StatusBadRequest)

		return
	}
	if s.config.StaticFS != nil {
		if _, err := fs.Stat(s.config.StaticFS, keyPath); err == nil {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			http.ServeFileFS(w, r, s.config.StaticFS, keyPath)

			return
		}
	}
	http.NotFound(w, r)
}

func (s *Server) handleFavicon(w http.ResponseWriter, r *http.Request) {
	if s.config.StaticFS != nil {
		faviconPath := "static/img/favicon-32x32.png"
		if _, err := fs.Stat(s.config.StaticFS, faviconPath); err == nil {
			http.ServeFileFS(w, r, s.config.StaticFS, faviconPath)

			return
		}
	}
	http.NotFound(w, r)
}

func (s *Server) handleRobots(w http.ResponseWriter, r *http.Request) {
	if s.config.StaticFS != nil {
		if _, err := fs.Stat(s.config.StaticFS, "robots.txt"); err == nil {
			http.ServeFileFS(w, r, s.config.StaticFS, "robots.txt")

			return
		}
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
