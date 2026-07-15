package website

import (
	"net/http"
)

// handleTriagePage handles serving the vulnerability triage UI page.
func (s *Server) handleTriagePage(w http.ResponseWriter, _ *http.Request) {
	// TODO: Serve triage page / template
	http.Error(w, "Triage UI page stub", http.StatusNotImplemented)
}

// handleTriageProxy handles proxying triage workflow actions.
func (s *Server) handleTriageProxy(w http.ResponseWriter, _ *http.Request) {
	// TODO: Proxy triage submission to backend service
	http.Error(w, "Triage proxy handler stub", http.StatusNotImplemented)
}
