package website

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/logger"
	"google.golang.org/protobuf/encoding/protojson"
)

// StartLinterRefresh warms the in-memory linter index immediately and refreshes it
// periodically until ctx is cancelled.
func (s *Server) StartLinterRefresh(ctx context.Context) {
	if s.linterIdx == nil {
		return
	}
	defer s.linterIdx.stop()

	if _, err := s.linterIdx.getSnapshot(ctx); err != nil && ctx.Err() == nil {
		logger.WarnContext(ctx, "initial linter index warmup failed", "error", err)
	}

	ticker := time.NewTicker(linterBackgroundRefresh)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			select {
			case <-ctx.Done():
				return
			case res := <-s.linterIdx.triggerRefresh(ctx):
				if res.Err != nil && ctx.Err() == nil {
					logger.WarnContext(ctx, "periodic linter index refresh failed", "error", res.Err)
				}
			}
		}
	}
}

func (s *Server) redirectProdLinter(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		if colonIdx := strings.IndexByte(host, ':'); colonIdx != -1 {
			host = host[:colonIdx]
		}

		if host == "api.osv.dev" {
			//nolint:gosec // G710: Hardcoded redirect target
			http.Redirect(w, r, "https://api.test.osv.dev"+r.URL.RequestURI(), http.StatusFound)

			return
		}
		if s.config.RedirectLinterToTest || host == "osv.dev" {
			//nolint:gosec // G710: Hardcoded redirect target
			http.Redirect(w, r, "https://test.osv.dev"+r.URL.RequestURI(), http.StatusFound)

			return
		}

		next(w, r)
	}
}

// handleLinterPage handles serving the linter findings UI page.
func (s *Server) handleLinterPage(w http.ResponseWriter, r *http.Request) {
	data := LinterPageData{
		Title:         "Vulnerability Linter Report - OSV",
		ActiveSection: "linter",
		APIURL:        s.config.APIURL,
	}

	s.renderStandalone(w, r, "linter.html", http.StatusOK, data)
}

func splitQueryList(values []string) []string {
	var out []string
	for _, raw := range values {
		for part := range strings.SplitSeq(raw, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				out = append(out, trimmed)
			}
		}
	}

	return out
}

// handleLinterQuery handles paginated server-side querying of cached linter findings.
func (s *Server) handleLinterQuery(w http.ResponseWriter, r *http.Request) {
	snap, err := s.linterIdx.getSnapshot(r.Context())
	if err != nil {
		logger.ErrorContext(r.Context(), "failed to load linter index snapshot", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)

		return
	}

	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	pageSize, _ := strconv.Atoi(q.Get("page_size"))

	resp := snap.query(linterQueryParams{
		Sources:    splitQueryList(q["source"]),
		SourceMode: q.Get("source_mode"),
		Codes:      splitQueryList(q["code"]),
		Categories: splitQueryList(q["cat"]),
		RuleMode:   q.Get("rule_mode"),
		Query:      q.Get("q"),
		Since:      q.Get("since"),
		Sort:       q.Get("sort"),
		Order:      q.Get("order"),
		Page:       page,
		PageSize:   pageSize,
	})

	s.renderJSON(w, r, http.StatusOK, resp)
}

// handleLinterVuln serves the full vulnerability JSON record from VulnerabilityStore for the linter inspector.
func (s *Server) handleLinterVuln(w http.ResponseWriter, r *http.Request) {
	bugID := r.PathValue("bug_id")
	if unescaped, err := url.PathUnescape(bugID); err == nil {
		bugID = unescaped
	}
	if bugID == "" || !vulnIDRegex.MatchString(bugID) {
		http.NotFound(w, r)

		return
	}

	vuln, err := s.stores.Vuln.GetFull(r.Context(), bugID)
	if errors.Is(err, models.ErrNotFound) {
		http.NotFound(w, r)

		return
	}
	if err != nil {
		logger.ErrorContext(r.Context(), "failed to get vulnerability for linter", "bug_id", bugID, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)

		return
	}

	data, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(vuln)
	if err != nil {
		logger.ErrorContext(r.Context(), "failed to marshal vulnerability JSON for linter", "bug_id", bugID, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(data); err != nil {
		logger.ErrorContext(r.Context(), "failed to write vulnerability JSON for linter", "bug_id", bugID, "error", err)
	}
}

// handleLinterSources handles listing sources that have linter findings from GCS.
func (s *Server) handleLinterSources(w http.ResponseWriter, r *http.Request) {
	infos, err := s.stores.Linter.ListSourceInfos(r.Context())
	if err != nil {
		logger.ErrorContext(r.Context(), "failed to list linter sources", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)

		return
	}

	sources := make([]string, len(infos))
	for i, info := range infos {
		sources[i] = info.Source
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(sources); err != nil {
		logger.ErrorContext(r.Context(), "failed to encode linter sources", "error", err)
	}
}

// handleLinterFindings handles fetching linter findings JSON for a specific source from GCS.
func (s *Server) handleLinterFindings(w http.ResponseWriter, r *http.Request) {
	source := r.PathValue("source")
	if source == "" {
		http.NotFound(w, r)

		return
	}

	findings, err := s.stores.Linter.GetFindings(r.Context(), source)
	if errors.Is(err, models.ErrNotFound) {
		http.NotFound(w, r)

		return
	}
	if err != nil {
		logger.ErrorContext(r.Context(), "failed to get linter findings", "source", source, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(findings); err != nil {
		logger.ErrorContext(r.Context(), "failed to write linter findings", "source", source, "error", err)
	}
}
