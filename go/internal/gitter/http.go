package gitter

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	pb "github.com/google/osv.dev/go/internal/gitter/pb/repository"
	"google.golang.org/protobuf/proto"
)

type httpClient struct {
	baseURL *url.URL
	client  *http.Client
}

// NewClient returns a fully initialized Gitter Client or an error.
func NewClient(hostURL string, client *http.Client) (Client, error) {
	parsedURL, err := url.Parse(hostURL)
	if err != nil {
		return nil, fmt.Errorf("invalid host URL %q: %w", hostURL, err)
	}
	if client == nil {
		client = http.DefaultClient
	}

	return &httpClient{baseURL: parsedURL, client: client}, nil
}

func (c *httpClient) do(ctx context.Context, method, path string, query url.Values, body proto.Message) (*http.Response, error) {
	reqURL := c.baseURL.JoinPath(path)
	if len(query) > 0 {
		reqURL.RawQuery = query.Encode()
	}

	var bodyReader io.Reader
	if body != nil {
		payload, err := proto.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed encoding request body: %w", err)
		}
		bodyReader = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL.String(), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed creating HTTP request: %w", err)
	}

	req.Header.Set("Accept", "application/x-protobuf")
	if body != nil {
		req.Header.Set("Content-Type", "application/x-protobuf")
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network execution failure: %w", err)
	}

	// Return all 2xx responses
	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
		return resp, nil
	}

	// Read error detail from response body up to 1KB.
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	resp.Body.Close()
	errMsg := strings.TrimSpace(string(bodyBytes))

	switch resp.StatusCode {
	case http.StatusForbidden:
		if errMsg != "" {
			return nil, fmt.Errorf("%w: %s", ErrRepoInaccessible, errMsg)
		}

		return nil, ErrRepoInaccessible
	case http.StatusNotFound:
		if errMsg != "" {
			return nil, fmt.Errorf("%w: %s", ErrRepoNotFound, errMsg)
		}

		return nil, ErrRepoNotFound
	case http.StatusBadRequest:
		if errMsg != "" {
			return nil, fmt.Errorf("%w: %s", ErrInvalidInput, errMsg)
		}

		return nil, ErrInvalidInput
	default:
		if errMsg != "" {
			return nil, fmt.Errorf("%w: status %d: %s", ErrInternalService, resp.StatusCode, errMsg)
		}

		return nil, fmt.Errorf("%w: received unexpected status code %d", ErrInternalService, resp.StatusCode)
	}
}

// GetGit handles GET /git (streaming tarball)
func (c *httpClient) GetGit(ctx context.Context, repoURL string, forceUpdate bool) (io.ReadCloser, error) {
	q := url.Values{}
	q.Set("url", repoURL)
	if forceUpdate {
		q.Set("force-update", "true")
	}

	resp, err := c.do(ctx, http.MethodGet, "/git", q, nil)
	if err != nil {
		return nil, err
	}

	return resp.Body, nil // Caller is responsible for closing the stream.
}

// Cache handles POST /cache (proactive background indexing)
func (c *httpClient) Cache(ctx context.Context, repoURL string) error {
	req := &pb.CacheRequest{
		Url: repoURL,
	}

	resp, err := c.do(ctx, http.MethodPost, "/cache", nil, req)
	if err != nil {
		return err
	}
	resp.Body.Close()

	return nil
}

// GetTags handles GET /tags (resolves ref list)
func (c *httpClient) GetTags(ctx context.Context, repoURL string) (*pb.TagsResponse, error) {
	q := url.Values{}
	q.Set("url", repoURL)

	resp, err := c.do(ctx, http.MethodGet, "/tags", q, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed reading tags response body: %w", err)
	}

	var tagsResp pb.TagsResponse
	if err := proto.Unmarshal(bodyBytes, &tagsResp); err != nil {
		return nil, fmt.Errorf("failed decoding tags response: %w", err)
	}

	return &tagsResp, nil
}

// GetAffectedCommits handles POST /affected-commits
func (c *httpClient) GetAffectedCommits(ctx context.Context, req *pb.AffectedCommitsRequest) (*pb.AffectedCommitsResponse, error) {
	resp, err := c.do(ctx, http.MethodPost, "/affected-commits", nil, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed reading affected commits response body: %w", err)
	}

	var affectedResp pb.AffectedCommitsResponse
	if err := proto.Unmarshal(bodyBytes, &affectedResp); err != nil {
		return nil, fmt.Errorf("failed decoding affected commits response: %w", err)
	}

	return &affectedResp, nil
}

// GetFileDiffs handles POST /file-diffs
func (c *httpClient) GetFileDiffs(ctx context.Context, req *pb.FileDiffsRequest) (*pb.FileDiffsResponse, error) {
	resp, err := c.do(ctx, http.MethodPost, "/file-diffs", nil, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed reading file diffs response body: %w", err)
	}

	var diffsResp pb.FileDiffsResponse
	if err := proto.Unmarshal(bodyBytes, &diffsResp); err != nil {
		return nil, fmt.Errorf("failed decoding file diffs response: %w", err)
	}

	return &diffsResp, nil
}

// GetFileContent handles POST /file-content
func (c *httpClient) GetFileContent(ctx context.Context, req *pb.FileContentRequest) (*pb.FileContentResponse, error) {
	resp, err := c.do(ctx, http.MethodPost, "/file-content", nil, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed reading file content response body: %w", err)
	}

	var fileContentResp pb.FileContentResponse
	if err := proto.Unmarshal(bodyBytes, &fileContentResp); err != nil {
		return nil, fmt.Errorf("failed decoding file content response: %w", err)
	}

	return &fileContentResp, nil
}

// Verify interface compliance at compile time.
var _ Client = (*httpClient)(nil)
