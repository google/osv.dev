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
	"strconv"
	"strings"
	"time"

	"github.com/google/osv.dev/go/logger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/api/idtoken"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	maxSandboxResponseBytes = 4 << 20 // 4 MiB max HTTP response from vanir-sandbox
	maxSandboxErrBodyBytes  = 1024    // Truncate error bodies before logging
	maxSandboxAttempts      = 3
	defaultRetryBackoff     = 500 * time.Millisecond
)

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

// HTTPSignatureGenerator invokes the remote Cloud Run vanir-sandbox service over
// Google OIDC-authenticated HTTPS (roles/run.invoker).
//
// TODO: Integrate with gitter's /commit-pack endpoint to relay cached shallow commit
// packs instead of having vanir-sandbox fetch directly from upstream Git hosts.
type HTTPSignatureGenerator struct {
	SandboxURL   string
	HTTPClient   *http.Client
	Timeout      time.Duration
	retryBackoff time.Duration
}

var _ SignatureGenerator = (*HTTPSignatureGenerator)(nil)

// NewHTTPSignatureGenerator creates an HTTPSignatureGenerator authenticated with Google OIDC
// identity tokens targeting sandboxURL (origin only, e.g. https://vanir-sandbox-xyz.run.app).
func NewHTTPSignatureGenerator(ctx context.Context, sandboxURL string) (*HTTPSignatureGenerator, error) {
	sandboxURL = strings.TrimRight(strings.TrimSpace(sandboxURL), "/")
	u, err := url.Parse(sandboxURL)
	if sandboxURL == "" || err != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" || u.User != nil ||
		u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("sandboxURL must be a valid https origin URL without path/query/userinfo: %q", sandboxURL)
	}
	origin := "https://" + u.Host

	httpClient, err := idtoken.NewClient(ctx, origin)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC HTTP client for %s: %w", origin, err)
	}
	httpClient.CheckRedirect = refuseRedirects

	return &HTTPSignatureGenerator{
		SandboxURL: origin,
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

func isRetryableSandboxStatus(code int) bool {
	return code == http.StatusTooManyRequests ||
		code == http.StatusBadGateway ||
		code == http.StatusServiceUnavailable ||
		code == http.StatusGatewayTimeout
}

func isValidSignatureValue(val *structpb.Value) bool {
	fields := val.GetStructValue().GetFields()
	if fields == nil {
		return false
	}
	for _, key := range []string{"id", "signature_type", "signature_version"} {
		if fields[key].GetStringValue() == "" {
			return false
		}
	}

	return true
}

func (g *HTTPSignatureGenerator) generateSingle(ctx context.Context, vuln *osvschema.Vulnerability) (map[int][]*structpb.Value, error) {
	vulnBytes, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(vuln)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal vulnerability %s: %w", vuln.GetId(), err)
	}
	reqPayload, err := json.Marshal(sandboxGenerateRequest{Vulnerability: json.RawMessage(vulnBytes)})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal sandbox request for %s: %w", vuln.GetId(), err)
	}

	timeout := g.Timeout
	if timeout <= 0 {
		timeout = defaultBatchTimeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	httpClient := g.HTTPClient
	if httpClient == nil {
		httpClient = noRedirectHTTPClient
	}
	backoff := g.retryBackoff
	if backoff <= 0 {
		backoff = defaultRetryBackoff
	}

	endpoint := strings.TrimRight(g.SandboxURL, "/") + "/v1/generate"
	var respBytes []byte
	var statusCode int
	for attempt := 1; attempt <= maxSandboxAttempts; attempt++ {
		httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(reqPayload))
		if err != nil {
			return nil, fmt.Errorf("failed to create sandbox request for %s: %w", vuln.GetId(), err)
		}
		httpReq.Header.Set("Content-Type", "application/json")

		resp, err := httpClient.Do(httpReq)
		if err != nil {
			return nil, fmt.Errorf("sandbox HTTP request failed for %s: %w", vuln.GetId(), err)
		}
		statusCode = resp.StatusCode
		respBytes, err = io.ReadAll(io.LimitReader(resp.Body, maxSandboxResponseBytes+1))
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to read sandbox response for %s: %w", vuln.GetId(), err)
		}
		if statusCode == http.StatusOK || !isRetryableSandboxStatus(statusCode) || attempt == maxSandboxAttempts {
			break
		}

		timer := time.NewTimer(backoff * time.Duration(attempt))
		select {
		case <-reqCtx.Done():
			timer.Stop()
			return nil, reqCtx.Err()
		case <-timer.C:
		}
	}

	if len(respBytes) > maxSandboxResponseBytes {
		return nil, fmt.Errorf("sandbox response for %s exceeds maximum size (%d bytes)", vuln.GetId(), maxSandboxResponseBytes)
	}
	if statusCode != http.StatusOK {
		errBody := strings.TrimSpace(string(respBytes))
		if len(errBody) > maxSandboxErrBodyBytes {
			errBody = strings.ToValidUTF8(errBody[:maxSandboxErrBodyBytes], "") + "... [truncated]"
		}

		return nil, fmt.Errorf("sandbox returned status %d for %s: %s", statusCode, vuln.GetId(), errBody)
	}

	var genResp sandboxGenerateResponse
	if err := json.Unmarshal(respBytes, &genResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal sandbox response for %s: %w", vuln.GetId(), err)
	}

	affectedLen := len(vuln.GetAffected())
	out := make(map[int][]*structpb.Value, len(genResp.Signatures))
	for idxStr, sigList := range genResp.Signatures {
		idx, err := strconv.Atoi(idxStr)
		if err != nil || idx < 0 || idx >= affectedLen || strconv.Itoa(idx) != idxStr {
			logger.ErrorContext(ctx, "Skipping vulnerability due to invalid affected index from sandbox",
				slog.String("id", vuln.GetId()), slog.String("index", idxStr))

			return map[int][]*structpb.Value{}, nil
		}
		vals := make([]*structpb.Value, 0, len(sigList))
		for _, rawSig := range sigList {
			var val structpb.Value
			if err := protojson.Unmarshal(rawSig, &val); err != nil || !isValidSignatureValue(&val) {
				logger.ErrorContext(ctx, "Skipping vulnerability due to malformed signature from sandbox",
					slog.String("id", vuln.GetId()), slog.Int("index", idx))

				return map[int][]*structpb.Value{}, nil
			}
			vals = append(vals, &val)
		}
		if len(vals) > 0 {
			out[idx] = vals
		}
	}

	return out, nil
}
