package website

import (
	"html/template"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"path"
	"regexp"

	"github.com/google/osv.dev/go/logger"
)

var validBlogName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func (s *Server) loadBlogContent(filePath string) (template.HTML, error) {
	fullPath := path.Join("static", "blog", filePath)
	content, err := fs.ReadFile(s.config.StaticFS, fullPath)
	if err != nil {
		return "", err
	}

	return template.HTML(content), nil //nolint:gosec // Trusted static content built by Hugo
}

// handleBlogIndex handles serving the blog landing page /blog/.
func (s *Server) handleBlogIndex(w http.ResponseWriter, r *http.Request) {
	indexHTML, err := s.loadBlogContent("index.html")
	if err != nil {
		s.RenderNotFound(w, r, "")

		return
	}

	data := BlogPageData{
		BasePageData: BasePageData{
			ActiveSection:     "blog",
			DisableTurboCache: false,
		},
		Index: indexHTML,
	}

	s.render(w, r, "blog.html", http.StatusOK, data)
}

// handleBlogRSS handles serving the blog RSS feed /blog/index.xml.
func (s *Server) handleBlogRSS(w http.ResponseWriter, r *http.Request) {
	fullPath := path.Join("static", "blog", "index.xml")
	rssContent, err := fs.ReadFile(s.config.StaticFS, fullPath)
	if err != nil {
		s.RenderNotFound(w, r, "")

		return
	}

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(rssContent); err != nil {
		logger.ErrorContext(r.Context(), "Failed to write blog RSS response", slog.Any("error", err))
	}
}

// handleBlogPost handles serving individual blog posts /blog/posts/{blog_name}/.
func (s *Server) handleBlogPost(w http.ResponseWriter, r *http.Request) {
	blogName := r.PathValue("blog_name")
	if blogName == "" || !validBlogName.MatchString(blogName) {
		s.RenderNotFound(w, r, "")

		return
	}

	postHTML, err := s.loadBlogContent(path.Join("posts", blogName, "index.html"))
	if err != nil {
		s.RenderNotFound(w, r, "")

		return
	}

	data := BlogPostPageData{
		BasePageData: BasePageData{
			ActiveSection:     "blog",
			DisableTurboCache: true,
		},
		Content: postHTML,
	}

	s.render(w, r, "blog_post.html", http.StatusOK, data)
}

// handleBlogPostFile handles serving static assets inside blog post directories /blog/posts/{blog_name}/{file_name}.
func (s *Server) handleBlogPostFile(w http.ResponseWriter, r *http.Request) {
	blogName := r.PathValue("blog_name")
	fileName := r.PathValue("file_name")
	if blogName == "" || fileName == "" || !validBlogName.MatchString(blogName) {
		s.RenderNotFound(w, r, "")

		return
	}

	assetPath := path.Join("static", "blog", "posts", blogName, path.Base(fileName))
	assetContent, err := fs.ReadFile(s.config.StaticFS, assetPath)
	if err != nil {
		s.RenderNotFound(w, r, "")

		return
	}

	contentType := mime.TypeByExtension(path.Ext(fileName))
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(assetContent); err != nil {
		logger.ErrorContext(r.Context(), "Failed to write blog asset response", slog.String("asset", assetPath), slog.Any("error", err))
	}
}
