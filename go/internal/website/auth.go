package website

import (
	"fmt"
	"net/http"
)

// handleLogin handles initiating Google OAuth authentication login flow.
// Query parameters:
//   - redirect: optional post-login redirect destination
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect")

	// TODO: Redirect user to Google OAuth authorization endpoint
	http.Error(w, fmt.Sprintf("OAuth login handler stub (redirect=%q)", redirectURI), http.StatusNotImplemented)
}

// handleAuthCallback handles processing OAuth callback tokens.
// Query parameters:
//   - code: authorization code from OAuth provider
//   - state: CSRF protection state token
func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	// TODO: Exchange code for session token and store in cookie
	http.Error(w, fmt.Sprintf("OAuth callback handler stub (code=%q, state=%q)", code, state), http.StatusNotImplemented)
}

// handleLogout handles logging out user and clearing authentication session cookies.
func (s *Server) handleLogout(w http.ResponseWriter, _ *http.Request) {
	// TODO: Clear authentication cookie and redirect user
	http.Error(w, "OAuth logout handler stub", http.StatusNotImplemented)
}
