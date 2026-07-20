// Package website provides HTTP handler logic for the OSV website.
package website

import (
	"bytes"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/google/osv.dev/go/logger"
)

const goVanityMetadata = `<meta name="go-import" content="osv.dev git https://github.com/google/osv.dev">`

// Config holds configuration options for the website server.
type Config struct {
	StaticFS    fs.FS
	DocsFS      fs.FS
	TemplateDir string
}

// Server handles website routing and HTTP requests.
type Server struct {
	config  Config
	mux     *http.ServeMux
	handler http.Handler
}

type responseLogger struct {
	http.ResponseWriter

	statusCode   int
	bytesWritten int64
}

func (r *responseLogger) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseLogger) Write(b []byte) (int, error) {
	if r.statusCode == 0 {
		r.statusCode = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytesWritten += int64(n)

	return n, err
}

// NewServer creates and initializes a new website Server.
// It returns an error if cfg.StaticFS or cfg.DocsFS is nil.
func NewServer(cfg Config) (*Server, error) {
	if cfg.StaticFS == nil {
		return nil, errors.New("StaticFS is required")
	}
	if cfg.DocsFS == nil {
		return nil, errors.New("DocsFS is required")
	}

	s := &Server{
		config: cfg,
		mux:    http.NewServeMux(),
	}
	s.registerRoutes()

	// Middlewares: Logging (if local/dev) -> ServeMux
	var h http.Handler = s.mux

	// Skip HTTP access logging in Cloud Run production to avoid duplicating Cloud Run infrastructure logs.
	if os.Getenv("K_SERVICE") == "" {
		h = loggingMiddleware(h)
	}

	s.handler = h

	return s, nil
}

// ServeHTTP implements the http.Handler interface by delegating to the middleware chain.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// loggingMiddleware returns an http.Handler that logs HTTP requests.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseLogger{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(rw, r)

		logger.InfoContext(r.Context(), "HTTP Request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", rw.statusCode),
			slog.Duration("duration", time.Since(start)),
			slog.Int64("bytes", rw.bytesWritten),
		)
	})
}

func (s *Server) registerRoutes() {
	// Health check
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)

	// Go vanity imports & root check
	s.mux.HandleFunc("GET /{$}", s.handleRoot)
	s.mux.HandleFunc("GET /bindings/go", s.handleGoBindingsVanity)

	// Simple redirects & static pages
	s.mux.HandleFunc("GET /about", s.handleRedirect("https://google.github.io/osv.dev/faq"))
	s.mux.HandleFunc("GET /faq", s.handleRedirect("https://google.github.io/osv.dev/faq"))
	s.mux.HandleFunc("GET /docs", s.handleRedirect("https://google.github.io/osv.dev"))
	s.mux.HandleFunc("GET /docs/", s.handleRedirect("https://google.github.io/osv.dev"))
	s.mux.HandleFunc("GET /ecosystems", s.handleRedirect("https://storage.googleapis.com/osv-vulnerabilities/ecosystems.txt"))

	// Static documentation & assets
	s.mux.HandleFunc("GET /docs/osv_service_v1.swagger.json", s.handleSwagger)
	s.mux.HandleFunc("GET /public_keys/{filename...}", s.handlePublicKeys)

	// Serve static directory if StaticFS is configured
	if s.config.StaticFS != nil {
		s.mux.Handle("GET /static/", http.FileServer(http.FS(s.config.StaticFS)))
	}

	// Static root assets
	s.mux.HandleFunc("GET /favicon.ico", s.handleFavicon)
	s.mux.HandleFunc("GET /robots.txt", s.handleRobots)

	// Vulnerability details & raw JSON
	s.mux.HandleFunc("GET /vulnerability/{vuln_id}", s.handleVulnerabilityDetails)
	s.mux.HandleFunc("GET /{potential_vuln_id}", s.handlePotentialVulnerability)

	// Blog routes (matching strict_slashes=False)
	s.mux.HandleFunc("GET /blog", s.handleBlogIndex)
	s.mux.HandleFunc("GET /blog/", s.handleBlogIndex)
	s.mux.HandleFunc("GET /blog/index.xml", s.handleBlogRSS)
	s.mux.HandleFunc("GET /blog/posts/{blog_name}", s.handleBlogPost)
	s.mux.HandleFunc("GET /blog/posts/{blog_name}/", s.handleBlogPost)
	s.mux.HandleFunc("GET /blog/posts/{blog_name}/{file_name}", s.handleBlogPostFile)

	// Vulnerability listing & search suggestions
	s.mux.HandleFunc("GET /list", s.handleList)
	s.mux.HandleFunc("GET /api/search_suggestions", s.handleSearchSuggestions)

	// Linter findings (matching strict_slashes=False)
	s.mux.HandleFunc("GET /linter", s.handleLinterPage)
	s.mux.HandleFunc("GET /linter/", s.handleLinterPage)
	s.mux.HandleFunc("GET /linter-findings", s.handleLinterSources)
	s.mux.HandleFunc("GET /linter-findings/", s.handleLinterSources)
	s.mux.HandleFunc("GET /linter-findings/{source}", s.handleLinterFindings)

	// Triage workflow
	s.mux.HandleFunc("GET /triage", s.handleTriagePage)
	s.mux.HandleFunc("POST /triage/proxy", s.handleTriageProxy)

	// Google OAuth authentication
	s.mux.HandleFunc("GET /login", s.handleLogin)
	s.mux.HandleFunc("GET /auth/callback", s.handleAuthCallback)
	s.mux.HandleFunc("GET /logout", s.handleLogout)
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, pageFile string, status int, data any) {
	templateDir := s.config.TemplateDir
	if templateDir == "" {
		templateDir = "go"
	}

	basePath := path.Join(templateDir, "base.html")
	pagePath := path.Join(templateDir, pageFile)

	tmpl, err := template.ParseFS(s.config.StaticFS, basePath, pagePath)
	if err != nil {
		logger.ErrorContext(r.Context(), "Failed to parse template", slog.String("page", pageFile), slog.Any("error", err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "base.html", data); err != nil {
		logger.ErrorContext(r.Context(), "Failed to execute template", slog.String("page", pageFile), slog.Any("error", err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)

		return
	}

	w.WriteHeader(status)
	if _, err := buf.WriteTo(w); err != nil {
		logger.ErrorContext(r.Context(), "Failed to write rendered template response", slog.String("page", pageFile), slog.Any("error", err))
	}
}
