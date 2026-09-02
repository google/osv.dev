package website

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/osv.dev/go/logger"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"
)

const (
	sessionCookieName    = "osv_session"
	oauthStateCookieName = "osv_oauth_state"
	sessionDuration      = 7 * 24 * time.Hour
	oauthStateDuration   = 10 * time.Minute
)

// AuthConfig contains Google OAuth2 configuration.
type AuthConfig struct {
	ClientID     string
	ClientSecret string
	SecretKey    string
	BypassOAuth  bool
}

type sessionPayload struct {
	Email     string `json:"email,omitempty"`
	State     string `json:"state,omitempty"`
	ExpiresAt int64  `json:"exp"`
}

func (s *Server) encryptCookie(payload sessionPayload) (string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(s.secretKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func (s *Server) decryptCookie(cookieVal string) (*sessionPayload, error) {
	data, err := base64.RawURLEncoding.DecodeString(cookieVal)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(s.secretKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("cookie too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	var payload sessionPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, err
	}

	if time.Now().Unix() > payload.ExpiresAt {
		return nil, errors.New("cookie expired")
	}

	return &payload, nil
}

func (s *Server) setEncryptedCookie(w http.ResponseWriter, name string, payload sessionPayload, duration time.Duration) error {
	encoded, err := s.encryptCookie(payload)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    encoded,
		Path:     "/",
		MaxAge:   int(duration.Seconds()),
		Expires:  time.Now().Add(duration),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	return nil
}

func (s *Server) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) oauthConfig(r *http.Request) *oauth2.Config {
	scheme := "http"
	if r.Header.Get("X-Forwarded-Proto") == "https" || r.TLS != nil {
		scheme = "https"
	}
	redirectURI := fmt.Sprintf("%s://%s/auth/callback", scheme, r.Host)

	return &oauth2.Config{
		ClientID:     s.config.Auth.ClientID,
		ClientSecret: s.config.Auth.ClientSecret,
		Endpoint:     google.Endpoint,
		RedirectURL:  redirectURI,
		Scopes:       []string{"openid", "email", "profile"},
	}
}

func (s *Server) requireGoogleAccount(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.config.Auth.BypassOAuth {
			next(w, r)

			return
		}

		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/login", http.StatusFound)

			return
		}

		payload, err := s.decryptCookie(cookie.Value)
		if err != nil || payload.Email == "" {
			http.Redirect(w, r, "/login", http.StatusFound)

			return
		}

		next(w, r)
	}
}

// handleLogin handles initiating Google OAuth authentication login flow.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.config.Auth.BypassOAuth {
		if err := s.setEncryptedCookie(w, sessionCookieName, sessionPayload{
			Email:     "dev@google.com",
			ExpiresAt: time.Now().Add(sessionDuration).Unix(),
		}, sessionDuration); err != nil {
			logger.ErrorContext(r.Context(), "failed to set session cookie", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)

			return
		}

		http.Redirect(w, r, "/triage", http.StatusFound)

		return
	}

	if s.config.Auth.ClientID == "" || s.config.Auth.ClientSecret == "" {
		s.renderJSON(w, r, http.StatusInternalServerError, map[string]string{
			"error": "OAuth credentials not configured. Set GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET env vars or enable BYPASS_OAUTH_FOR_LOCAL_DEV.",
		})

		return
	}

	stateBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, stateBytes); err != nil {
		logger.ErrorContext(r.Context(), "failed to generate oauth state", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)

		return
	}
	state := hex.EncodeToString(stateBytes)

	if err := s.setEncryptedCookie(w, oauthStateCookieName, sessionPayload{
		State:     state,
		ExpiresAt: time.Now().Add(oauthStateDuration).Unix(),
	}, oauthStateDuration); err != nil {
		logger.ErrorContext(r.Context(), "failed to set oauth state cookie", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)

		return
	}

	conf := s.oauthConfig(r)
	http.Redirect(w, r, conf.AuthCodeURL(state, oauth2.AccessTypeOffline), http.StatusFound)
}

// handleAuthCallback handles processing OAuth callback tokens.
func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(oauthStateCookieName)
	if err != nil || cookie.Value == "" {
		s.renderJSON(w, r, http.StatusBadRequest, map[string]string{
			"error": "Invalid state parameter",
		})

		return
	}

	s.clearCookie(w, oauthStateCookieName)

	statePayload, err := s.decryptCookie(cookie.Value)
	if err != nil || statePayload.State == "" {
		s.renderJSON(w, r, http.StatusBadRequest, map[string]string{
			"error": "Invalid state parameter",
		})

		return
	}

	queryState := r.URL.Query().Get("state")
	if subtle.ConstantTimeCompare([]byte(queryState), []byte(statePayload.State)) != 1 {
		s.renderJSON(w, r, http.StatusBadRequest, map[string]string{
			"error": "Invalid state parameter",
		})

		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		s.renderJSON(w, r, http.StatusBadRequest, map[string]string{
			"error": "Missing code parameter",
		})

		return
	}

	conf := s.oauthConfig(r)
	token, err := conf.Exchange(r.Context(), code)
	if err != nil {
		logger.ErrorContext(r.Context(), "failed to exchange oauth code", "error", err)
		s.renderJSON(w, r, http.StatusBadRequest, map[string]string{
			"error": "Failed to obtain ID token. Maybe credentials mismatch or invalid code.",
		})

		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		s.renderJSON(w, r, http.StatusBadRequest, map[string]string{
			"error": "Missing ID token in token response",
		})

		return
	}

	payload, err := idtoken.Validate(r.Context(), rawIDToken, s.config.Auth.ClientID)
	if err != nil {
		logger.ErrorContext(r.Context(), "invalid oauth id token", "error", err)
		s.renderJSON(w, r, http.StatusBadRequest, map[string]string{
			"error": "Invalid token",
		})

		return
	}

	email, _ := payload.Claims["email"].(string)
	if email == "" {
		s.renderJSON(w, r, http.StatusBadRequest, map[string]string{
			"error": "Token missing email claim",
		})

		return
	}

	if err := s.setEncryptedCookie(w, sessionCookieName, sessionPayload{
		Email:     email,
		ExpiresAt: time.Now().Add(sessionDuration).Unix(),
	}, sessionDuration); err != nil {
		logger.ErrorContext(r.Context(), "failed to set session cookie", "error", err)
		s.renderJSON(w, r, http.StatusInternalServerError, map[string]string{
			"error": "Failed to set session",
		})

		return
	}

	http.Redirect(w, r, "/triage", http.StatusFound)
}

// handleLogout handles logging out user and clearing authentication session cookies.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.clearCookie(w, sessionCookieName)
	s.clearCookie(w, oauthStateCookieName)

	http.Redirect(w, r, "/triage", http.StatusFound)
}
