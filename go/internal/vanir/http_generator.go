// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vanir

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/osv.dev/go/logger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/api/idtoken"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	maxSandboxResponseBytes = 4 << 20 // 4 MiB max HTTP response from vanir-sandbox
	maxSandboxRequestBytes  = 4 << 20 // Matches vanir-sandbox maxRequestBytes
	maxSandboxErrBodyBytes  = 1024    // Truncate error bodies before logging
)

var commitHashRegex = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

func refuseRedirects(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

var noRedirectHTTPClient = &http.Client{CheckRedirect: refuseRedirects}

type sandboxGenerateRequest struct {
	Vulnerability json.RawMessage `json:"vulnerability"`
}

type sandboxGenerateResponse struct {
	Signatures map[string][]json.RawMessage `json:"signatures"`
}

func normalizeGitRepoURL(raw string) (string, bool) {
	if raw == "" || strings.HasPrefix(raw, "-") || strings.ContainsFunc(raw, func(r rune) bool { return r <= 0x20 || r == 0x7f }) {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Path == "" || u.Path == "/" {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "git" && strings.EqualFold(u.Hostname(), "github.com") {
		scheme = "https"
	}
	if scheme != "https" && scheme != "http" {
		return "", false
	}
	u.Scheme = scheme
	u.Host = strings.ToLower(u.Host)
	u.RawQuery = ""
	u.Fragment = ""

	return u.String(), true
}

// prepareVulnForSandbox clones v and strips non-URL Git repos and non-hash fixed events,
// returning whether any valid Git target or ecosystem_specific.fixes entry remains.
func prepareVulnForSandbox(v *osvschema.Vulnerability) (*osvschema.Vulnerability, bool) {
	clone := proto.CloneOf(v)
	hasWork := false

	for _, aff := range clone.GetAffected() {
		if aff == nil {
			continue
		}
		if len(aff.GetEcosystemSpecific().GetFields()["fixes"].GetListValue().GetValues()) > 0 {
			hasWork = true
		}

		keptRanges := make([]*osvschema.Range, 0, len(aff.GetRanges()))
		for _, r := range aff.GetRanges() {
			if r == nil {
				continue
			}
			if r.GetType() != osvschema.Range_GIT {
				keptRanges = append(keptRanges, r)
				continue
			}
			repoURL, ok := normalizeGitRepoURL(r.GetRepo())
			if !ok {
				continue
			}

			validEvents := make([]*osvschema.Event, 0, len(r.GetEvents()))
			for _, ev := range r.GetEvents() {
				fixed := strings.ToLower(ev.GetFixed())
				if !commitHashRegex.MatchString(fixed) {
					continue
				}
				validEvents = append(validEvents, &osvschema.Event{Fixed: fixed})
			}
			if len(validEvents) == 0 {
				continue
			}
			r.Repo = repoURL
			r.Events = validEvents
			keptRanges = append(keptRanges, r)
			hasWork = true
		}
		aff.Ranges = keptRanges
	}

	return clone, hasWork
}

func parseSandboxSignatures(origVuln *osvschema.Vulnerability, rawAffected map[string][]json.RawMessage) (map[int][]*structpb.Value, error) {
	affectedLen := len(origVuln.GetAffected())
	out := make(map[int][]*structpb.Value, len(rawAffected))
	for idxStr, sigList := range rawAffected {
		idx, err := strconv.Atoi(idxStr)
		if err != nil || idx < 0 || idx >= affectedLen {
			return nil, fmt.Errorf("invalid affected index %q for %s (len=%d)", idxStr, origVuln.GetId(), affectedLen)
		}
		vals := make([]*structpb.Value, 0, len(sigList))
		for _, rawSig := range sigList {
			var val structpb.Value
			if err := protojson.Unmarshal(rawSig, &val); err != nil {
				return nil, fmt.Errorf("failed to parse signature for %s: %w", origVuln.GetId(), err)
			}
			vals = append(vals, &val)
		}
		if len(vals) > 0 {
			out[idx] = vals
		}
	}

	return out, nil
}

// HTTPSignatureGenerator is the orchestrator-side SignatureGenerator used by
// vanir_signatures when VANIR_SANDBOX_URL is configured. For each vulnerability it
// strips invalid Git repo URLs, POSTs the record to the Cloud Run vanir-sandbox
// service over Google OIDC-authenticated HTTP (roles/run.invoker), and parses the
// returned signatures back into OSV structpb.Value entries.
//
// TODO: Integrate with gitter's /commit-pack endpoint to relay cached shallow commit
// packs instead of having vanir-sandbox fetch directly from upstream Git hosts.
type HTTPSignatureGenerator struct {
	SandboxURL string
	HTTPClient *http.Client
	Timeout    time.Duration
}

var _ SignatureGenerator = (*HTTPSignatureGenerator)(nil)

// NewHTTPSignatureGenerator creates an HTTPSignatureGenerator authenticated with Google OIDC
// identity tokens targeting sandboxURL (for Cloud Run IAM roles/run.invoker).
func NewHTTPSignatureGenerator(ctx context.Context, sandboxURL string) (*HTTPSignatureGenerator, error) {
	sandboxURL = strings.TrimRight(strings.TrimSpace(sandboxURL), "/")
	u, err := url.Parse(sandboxURL)
	if sandboxURL == "" || err != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("sandboxURL must be a valid https URL without userinfo: %q", sandboxURL)
	}

	httpClient, err := idtoken.NewClient(ctx, sandboxURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC HTTP client for %s: %w", sandboxURL, err)
	}
	httpClient.Timeout = defaultBatchTimeout
	httpClient.CheckRedirect = refuseRedirects

	return &HTTPSignatureGenerator{
		SandboxURL: sandboxURL,
		HTTPClient: httpClient,
		Timeout:    defaultBatchTimeout,
	}, nil
}

func (g *HTTPSignatureGenerator) GenerateBatch(ctx context.Context, vulns []*osvschema.Vulnerability, _ string) (SignatureMap, error) {
	result := make(SignatureMap, len(vulns))
	for _, v := range vulns {
		if v == nil {
			continue
		}
		sigs, err := g.generateSingle(ctx, v)
		if err != nil {
			return nil, err
		}
		if len(sigs) > 0 {
			result[v.GetId()] = sigs
		}
	}

	return result, nil
}

func (g *HTTPSignatureGenerator) generateSingle(ctx context.Context, origVuln *osvschema.Vulnerability) (map[int][]*structpb.Value, error) {
	sanitized, hasWork := prepareVulnForSandbox(origVuln)
	if !hasWork {
		return map[int][]*structpb.Value{}, nil
	}

	vulnBytes, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(sanitized)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal sanitized vulnerability %s: %w", origVuln.GetId(), err)
	}
	reqPayload, err := json.Marshal(sandboxGenerateRequest{
		Vulnerability: json.RawMessage(vulnBytes),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal sandbox request for %s: %w", origVuln.GetId(), err)
	}
	if len(reqPayload) > maxSandboxRequestBytes {
		logger.WarnContext(ctx, "Skipping vulnerability exceeding sandbox request size", slog.String("id", origVuln.GetId()), slog.Int("bytes", len(reqPayload)))
		return map[int][]*structpb.Value{}, nil
	}

	timeout := g.Timeout
	if timeout <= 0 {
		timeout = defaultBatchTimeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, strings.TrimRight(g.SandboxURL, "/")+"/v1/generate", bytes.NewReader(reqPayload))
	if err != nil {
		return nil, fmt.Errorf("failed to create sandbox request for %s: %w", origVuln.GetId(), err)
	}
	httpReq.GetBody = nil
	httpReq.Header.Set("Content-Type", "application/json")

	httpClient := g.HTTPClient
	if httpClient == nil {
		httpClient = noRedirectHTTPClient
	}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("sandbox HTTP request failed for %s: %w", origVuln.GetId(), err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxSandboxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read sandbox response for %s: %w", origVuln.GetId(), err)
	}
	if len(respBytes) > maxSandboxResponseBytes {
		return nil, fmt.Errorf("sandbox response for %s exceeds maximum size (%d bytes)", origVuln.GetId(), maxSandboxResponseBytes)
	}
	if resp.StatusCode != http.StatusOK {
		errBody := strings.TrimSpace(string(respBytes))
		if len(errBody) > maxSandboxErrBodyBytes {
			errBody = strings.ToValidUTF8(errBody[:maxSandboxErrBodyBytes], "") + "... [truncated]"
		}

		return nil, fmt.Errorf("sandbox returned status %d for %s: %s", resp.StatusCode, origVuln.GetId(), errBody)
	}

	var genResp sandboxGenerateResponse
	if err := json.Unmarshal(respBytes, &genResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal sandbox response for %s: %w", origVuln.GetId(), err)
	}

	parsed, err := parseSandboxSignatures(origVuln, genResp.Signatures)
	if err != nil {
		logger.ErrorContext(ctx, "Skipping vulnerability due to invalid sandbox signatures", slog.String("id", origVuln.GetId()), slog.Any("error", err))
		return map[int][]*structpb.Value{}, nil
	}

	return parsed, nil
}
