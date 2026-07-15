package website

import (
	"fmt"
	"net/http"
)

// handleBlogIndex handles serving the blog landing page /blog/.
func (s *Server) handleBlogIndex(w http.ResponseWriter, _ *http.Request) {
	// TODO: Load blog index content from StaticFS (static/blog/index.html) and render blog template
	http.Error(w, "Blog index handler stub", http.StatusNotImplemented)
}

// handleBlogRSS handles serving the blog RSS feed /blog/index.xml.
func (s *Server) handleBlogRSS(w http.ResponseWriter, _ *http.Request) {
	// TODO: Serve static/blog/index.xml from StaticFS
	http.Error(w, "Blog RSS handler stub", http.StatusNotImplemented)
}

// handleBlogPost handles serving individual blog posts /blog/posts/{blog_name}/.
func (s *Server) handleBlogPost(w http.ResponseWriter, r *http.Request) {
	blogName := r.PathValue("blog_name")
	if blogName == "" {
		http.NotFound(w, r)

		return
	}

	// TODO: Validate blog_name, load static/blog/posts/{blog_name}/index.html and render post template
	http.Error(w, fmt.Sprintf("Blog post handler stub (blogName=%q)", blogName), http.StatusNotImplemented)
}

// handleBlogPostFile handles serving static assets inside blog post directories /blog/posts/{blog_name}/{file_name}.
func (s *Server) handleBlogPostFile(w http.ResponseWriter, r *http.Request) {
	blogName := r.PathValue("blog_name")
	fileName := r.PathValue("file_name")
	if blogName == "" || fileName == "" {
		http.NotFound(w, r)

		return
	}

	// TODO: Serve static/blog/posts/{blog_name}/{file_name} from StaticFS
	http.Error(w, fmt.Sprintf("Blog post asset handler stub (blogName=%q, fileName=%q)", blogName, fileName), http.StatusNotImplemented)
}
