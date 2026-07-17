package website

import (
	"fmt"
	"net/http"
)

// handleList handles rendering the vulnerability listing page and backing paginated list queries.
// Query parameters:
//   - q: search query string
//   - ecosystem: ecosystem filter
//   - page: page number
func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	ecosystem := r.URL.Query().Get("ecosystem")
	page := r.URL.Query().Get("page")

	// TODO: Query ListedVulnerability entities from Datastore and render page / JSON
	http.Error(w, fmt.Sprintf("Vulnerability list handler stub (q=%q, ecosystem=%q, page=%q)", q, ecosystem, page), http.StatusNotImplemented)
}
