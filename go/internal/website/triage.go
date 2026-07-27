package website

import (
	"net/http"
)

// handleTriagePage handles serving the vulnerability triage UI page.
func (s *Server) handleTriagePage(w http.ResponseWriter, r *http.Request) {
	data := TriagePageData{
		BasePageData: BasePageData{
			ActiveSection: "triage",
		},
		Columns: []int{1, 2, 3},
	}

	s.render(w, r, "triage.html", http.StatusOK, data)
}

// handleTriageProxy handles proxying triage workflow actions.
func (s *Server) handleTriageProxy(w http.ResponseWriter, _ *http.Request) {
	// TODO: Proxy triage submission to backend service
	http.Error(w, "Triage proxy handler stub", http.StatusNotImplemented)
}
