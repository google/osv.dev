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
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/osv.dev/go/internal/gitter"
	pb "github.com/google/osv.dev/go/internal/gitter/pb/repository"
	"github.com/google/osv.dev/go/logger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"golang.org/x/sync/singleflight"
	"google.golang.org/api/idtoken"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	defaultPackCacheMaxBytes = 128 << 20 // 128 MiB in-memory commit-pack LRU cache
	maxSandboxResponseBytes  = 4 << 20   // 4 MiB max HTTP response from vanir-sandbox
	maxSandboxRequestBytes   = 64 << 20  // Matches vanir-sandbox maxRequestBytes
	maxTotalRepoPackBytes    = 44 << 20  // Keeps base64-encoded JSON payload comfortably under 64 MiB
	defaultGitterPackTimeout = 5 * time.Minute
)

type sandboxGenerateRequest struct {
	Vulnerability json.RawMessage   `json:"vulnerability"`
	RepoPacks     map[string][]byte `json:"repo_packs"`
	AllowNetwork  bool              `json:"allow_network"`
}

type sandboxGenerateResponse struct {
	Signatures map[string][]any `json:"signatures"`
}

// commitPackCache is a thread-safe, byte-bounded LRU cache for gitter commit packs.
type commitPackCache struct {
	mu       sync.Mutex
	maxBytes int64
	curBytes int64
	ll       *list.List
	items    map[string]*list.Element
}

type packCacheEntry struct {
	key  string
	data []byte
}

func newCommitPackCache(maxBytes int64) *commitPackCache {
	return &commitPackCache{
		maxBytes: maxBytes,
		ll:       list.New(),
		items:    make(map[string]*list.Element),
	}
}

func (c *commitPackCache) get(key string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	c.ll.MoveToFront(el)

	return el.Value.(*packCacheEntry).data, true
}

func (c *commitPackCache) put(key string, data []byte) {
	size := int64(len(data))
	if size <= 0 || size > c.maxBytes {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.items[key]; ok {
		entry := el.Value.(*packCacheEntry)
		c.curBytes -= int64(len(entry.data))
		entry.data = data
		c.curBytes += size
		c.ll.MoveToFront(el)
	} else {
		el := c.ll.PushFront(&packCacheEntry{key: key, data: data})
		c.items[key] = el
		c.curBytes += size
	}

	for c.curBytes > c.maxBytes && c.ll.Len() > 0 {
		back := c.ll.Back()
		c.ll.Remove(back)
		entry := back.Value.(*packCacheEntry)
		delete(c.items, entry.key)
		c.curBytes -= int64(len(entry.data))
	}
}

// HTTPSignatureGenerator invokes the remote Cloud Run vanir-sandbox service over IAM OIDC
// authenticated HTTP, pre-fetching shallow commit packs from gitter so the sandbox runs
// without external GitHub bandwidth or VPC access.
type HTTPSignatureGenerator struct {
	SandboxURL   string
	HTTPClient   *http.Client
	GitterClient gitter.Client
	Timeout      time.Duration

	initOnce  sync.Once
	packCache *commitPackCache
	packSF    singleflight.Group
}

var _ SignatureGenerator = (*HTTPSignatureGenerator)(nil)

// NewHTTPSignatureGenerator creates an HTTPSignatureGenerator authenticated with Google OIDC
// identity tokens targeting sandboxURL (for Cloud Run IAM roles/run.invoker).
func NewHTTPSignatureGenerator(ctx context.Context, sandboxURL string, gitterClient gitter.Client) (*HTTPSignatureGenerator, error) {
	sandboxURL = strings.TrimRight(strings.TrimSpace(sandboxURL), "/")
	if sandboxURL == "" {
		return nil, errors.New("sandboxURL must not be empty")
	}

	httpClient, err := idtoken.NewClient(ctx, sandboxURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC HTTP client for %s: %w", sandboxURL, err)
	}
	httpClient.Timeout = defaultBatchTimeout

	return &HTTPSignatureGenerator{
		SandboxURL:   sandboxURL,
		HTTPClient:   httpClient,
		GitterClient: gitterClient,
		Timeout:      defaultBatchTimeout,
		packCache:    newCommitPackCache(defaultPackCacheMaxBytes),
	}, nil
}

func (g *HTTPSignatureGenerator) ensureCache() {
	g.initOnce.Do(func() {
		if g.packCache == nil {
			g.packCache = newCommitPackCache(defaultPackCacheMaxBytes)
		}
	})
}

func (g *HTTPSignatureGenerator) getCommitPack(ctx context.Context, repoURL string, commits []string, refID string) ([]byte, error) {
	g.ensureCache()
	sortedCommits := slices.Clone(commits)
	slices.Sort(sortedCommits)
	cacheKey := repoURL + "\x00" + strings.Join(sortedCommits, ",")

	if cached, ok := g.packCache.get(cacheKey); ok {
		return cached, nil
	}

	ch := g.packSF.DoChan(cacheKey, func() (any, error) {
		if cached, ok := g.packCache.get(cacheKey); ok {
			return cached, nil
		}
		// Detach from the first caller's context so cancelling one worker does not poison
		// concurrent waiters sharing the same singleflight fetch.
		fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultGitterPackTimeout)
		defer cancel()

		packBytes, err := g.GitterClient.GetCommitPack(fetchCtx, &pb.CommitPackRequest{
			Url:     repoURL,
			Commits: sortedCommits,
			RefId:   refID,
		})
		if err != nil {
			return nil, err
		}
		g.packCache.put(cacheKey, packBytes)

		return packBytes, nil
	})

	select {
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}

		return res.Val.([]byte), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func stripReposFromVuln(v *osvschema.Vulnerability, skippedRepos map[string]struct{}) {
	for _, aff := range v.GetAffected() {
		if len(aff.GetRanges()) == 0 {
			continue
		}
		kept := make([]*osvschema.Range, 0, len(aff.GetRanges()))
		for _, r := range aff.GetRanges() {
			if r.GetType() == osvschema.Range_GIT {
				if _, skip := skippedRepos[r.GetRepo()]; skip {
					continue
				}
			}
			kept = append(kept, r)
		}
		aff.Ranges = kept
	}
}

func (g *HTTPSignatureGenerator) GenerateBatch(ctx context.Context, vulns []*osvschema.Vulnerability, _ string) (SignatureMap, error) {
	if len(vulns) == 0 {
		return SignatureMap{}, nil
	}

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
			// Strictly pin output to the requested vulnerability ID.
			result[v.GetId()] = sigs
		}
	}

	return result, nil
}

func (g *HTTPSignatureGenerator) generateSingle(ctx context.Context, origVuln *osvschema.Vulnerability) (map[int][]*structpb.Value, error) {
	sanitized, gitTargets, needsNetwork, indexMap := sanitizeForVanirWithIndexMap(origVuln)
	if len(gitTargets) == 0 && !needsNetwork {
		return map[int][]*structpb.Value{}, nil
	}

	repoPacks := make(map[string][]byte, len(gitTargets))
	allowNetwork := needsNetwork

	if g.GitterClient != nil && len(gitTargets) > 0 {
		repoURLs := make([]string, 0, len(gitTargets))
		for repoURL := range gitTargets {
			repoURLs = append(repoURLs, repoURL)
		}
		slices.Sort(repoURLs)

		skippedRepos := make(map[string]struct{})
		var totalPackBytes int
		for _, repoURL := range repoURLs {
			packBytes, err := g.getCommitPack(ctx, repoURL, gitTargets[repoURL], origVuln.GetId())
			if err != nil {
				if errors.Is(err, gitter.ErrRepoNotFound) || errors.Is(err, gitter.ErrRepoInaccessible) || errors.Is(err, gitter.ErrPackTooLarge) {
					logger.WarnContext(ctx, "Skipping inaccessible, missing, or oversized repo for Vanir commit pack",
						slog.String("id", origVuln.GetId()),
						slog.String("repo", repoURL),
						slog.Any("error", err))
					skippedRepos[repoURL] = struct{}{}

					continue
				}

				return nil, fmt.Errorf("failed to fetch commit pack from gitter for %s (%s): %w", origVuln.GetId(), repoURL, err)
			}
			if totalPackBytes+len(packBytes) > maxTotalRepoPackBytes {
				logger.WarnContext(ctx, "Skipping repo commit pack that would exceed sandbox payload limit",
					slog.String("id", origVuln.GetId()),
					slog.String("repo", repoURL),
					slog.Int("pack_bytes", len(packBytes)),
					slog.Int("total_pack_bytes", totalPackBytes))
				skippedRepos[repoURL] = struct{}{}

				continue
			}
			totalPackBytes += len(packBytes)
			repoPacks[repoURL] = packBytes
		}

		if len(skippedRepos) > 0 {
			stripReposFromVuln(sanitized, skippedRepos)
		}
	} else if len(gitTargets) > 0 {
		allowNetwork = true
	}

	if len(repoPacks) == 0 && !allowNetwork {
		return map[int][]*structpb.Value{}, nil
	}

	marshaler := protojson.MarshalOptions{UseProtoNames: true}
	vulnBytes, err := marshaler.Marshal(sanitized)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal sanitized vulnerability %s: %w", origVuln.GetId(), err)
	}

	reqPayload, err := json.Marshal(sandboxGenerateRequest{
		Vulnerability: json.RawMessage(vulnBytes),
		RepoPacks:     repoPacks,
		AllowNetwork:  allowNetwork,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal sandbox request for %s: %w", origVuln.GetId(), err)
	}
	if len(reqPayload) > maxSandboxRequestBytes {
		logger.WarnContext(ctx, "Skipping vulnerability whose sandbox request exceeds max payload size",
			slog.String("id", origVuln.GetId()),
			slog.Int("payload_bytes", len(reqPayload)))

		return map[int][]*structpb.Value{}, nil
	}

	timeout := g.Timeout
	if timeout <= 0 {
		timeout = defaultBatchTimeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	endpoint := strings.TrimRight(g.SandboxURL, "/") + "/v1/generate"
	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(reqPayload))
	if err != nil {
		return nil, fmt.Errorf("failed to create sandbox HTTP request for %s: %w", origVuln.GetId(), err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpClient := g.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
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
		return nil, fmt.Errorf("sandbox returned status %d for %s: %s", resp.StatusCode, origVuln.GetId(), strings.TrimSpace(string(respBytes)))
	}

	var genResp sandboxGenerateResponse
	if err := json.Unmarshal(respBytes, &genResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal sandbox response for %s: %w", origVuln.GetId(), err)
	}

	remapped, err := remapAffectedIndices(sanitized, genResp.Signatures, indexMap)
	if err != nil {
		return nil, fmt.Errorf("invalid affected index from sandbox for %s: %w", origVuln.GetId(), err)
	}

	validated, err := ValidateSignatures(origVuln, remapped)
	if err != nil {
		return nil, fmt.Errorf("signature validation failed for %s: %w", origVuln.GetId(), err)
	}

	return validated, nil
}
