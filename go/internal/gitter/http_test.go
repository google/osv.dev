package gitter_test

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv.dev/go/internal/gitter"
	pb "github.com/google/osv.dev/go/internal/gitter/pb/repository"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func hexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("failed decoding hex string %q: %v", s, err)
	}

	return b
}

func TestNewClient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		hostURL string
		client  *http.Client
		wantErr bool
	}{
		{
			name:    "valid URL",
			hostURL: "http://localhost:8080",
			client:  nil,
			wantErr: false,
		},
		{
			name:    "invalid URL",
			hostURL: ":%invalid",
			client:  nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, err := gitter.NewClient(tt.hostURL, tt.client)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewClient(%q) error = %v, wantErr = %v", tt.hostURL, err, tt.wantErr)
			}
			if !tt.wantErr && c == nil {
				t.Fatal("NewClient() returned nil client without error")
			}
		})
	}
}

func TestGetGit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		repoURL     string
		forceUpdate bool
		statusCode  int
		respData    string
		wantData    string
		wantErr     error
	}{
		{
			name:        "success with force update",
			repoURL:     "https://github.com/google/oss-fuzz-vulns.git",
			forceUpdate: true,
			statusCode:  http.StatusOK,
			respData:    "tarball-content",
			wantData:    "tarball-content",
		},
		{
			name:       "forbidden repo mapping",
			repoURL:    "https://github.com/google/this-repo-does-not-exist-12345.git",
			statusCode: http.StatusForbidden,
			respData:   "Authentication failed",
			wantErr:    gitter.ErrRepoInaccessible,
		},
		{
			name:       "not found error mapping",
			repoURL:    "https://github.com/google/oss-fuzz-vulns.git",
			statusCode: http.StatusNotFound,
			respData:   "Repository not found",
			wantErr:    gitter.ErrRepoNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.statusCode == http.StatusOK {
					if r.Method != http.MethodGet || r.URL.Path != "/git" {
						t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					}
					if got := r.URL.Query().Get("url"); got != tt.repoURL {
						t.Errorf("unexpected url query: %s", got)
					}
				}
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.respData))
			}))
			t.Cleanup(ts.Close)

			client, err := gitter.NewClient(ts.URL, nil)
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			rc, err := client.GetGit(context.Background(), tt.repoURL, tt.forceUpdate)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("GetGit() error = %v, wantErr = %v", err, tt.wantErr)
				}

				return
			}
			if err != nil {
				t.Fatalf("unexpected GetGit() error: %v", err)
			}
			defer rc.Close()

			data, err := io.ReadAll(rc)
			if err != nil {
				t.Fatalf("failed reading response body: %v", err)
			}
			if string(data) != tt.wantData {
				t.Errorf("GetGit() data = %q, want %q", string(data), tt.wantData)
			}
		})
	}
}

func TestCache(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		repoURL    string
		statusCode int
		wantErr    error
	}{
		{
			name:       "success",
			repoURL:    "https://github.com/google/oss-fuzz-vulns.git",
			statusCode: http.StatusOK,
		},
		{
			name:       "error mapping",
			repoURL:    "https://github.com/google/this-repo-does-not-exist-12345.git",
			statusCode: http.StatusForbidden,
			wantErr:    gitter.ErrRepoInaccessible,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.statusCode == http.StatusOK {
					if r.Method != http.MethodPost || r.URL.Path != "/cache" {
						t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					}
					bodyBytes, _ := io.ReadAll(r.Body)
					var req pb.CacheRequest
					_ = proto.Unmarshal(bodyBytes, &req)
					if req.GetUrl() != tt.repoURL {
						t.Errorf("expected URL %q, got %q", tt.repoURL, req.GetUrl())
					}
				}
				w.WriteHeader(tt.statusCode)
			}))
			t.Cleanup(ts.Close)

			client, err := gitter.NewClient(ts.URL, nil)
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			err = client.Cache(context.Background(), tt.repoURL)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Cache() error = %v, wantErr = %v", err, tt.wantErr)
				}

				return
			}
			if err != nil {
				t.Fatalf("unexpected Cache() error: %v", err)
			}
		})
	}
}

func TestGetTags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		repoURL    string
		statusCode int
		respProto  *pb.TagsResponse
		wantResp   *pb.TagsResponse
		wantErr    error
	}{
		{
			name:       "success",
			repoURL:    "https://github.com/oliverchang/osv-test.git",
			statusCode: http.StatusOK,
			respProto: &pb.TagsResponse{
				Tags: []*pb.Ref{
					{Label: "v0.1", Hash: hexDecode(t, "a2ba949290915d445d34d0e8e9de2e7ce38198fc")},
					{Label: "v0.2", Hash: hexDecode(t, "8d8242f545e9cec3e6d0d2e3f5bde8be1c659735")},
				},
			},
			wantResp: &pb.TagsResponse{
				Tags: []*pb.Ref{
					{Label: "v0.1", Hash: hexDecode(t, "a2ba949290915d445d34d0e8e9de2e7ce38198fc")},
					{Label: "v0.2", Hash: hexDecode(t, "8d8242f545e9cec3e6d0d2e3f5bde8be1c659735")},
				},
			},
		},
		{
			name:       "error mapping",
			repoURL:    "https://github.com/google/this-repo-does-not-exist-12345.git",
			statusCode: http.StatusForbidden,
			wantErr:    gitter.ErrRepoInaccessible,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.statusCode)
				if tt.statusCode == http.StatusOK && tt.respProto != nil {
					w.Header().Set("Content-Type", "application/x-protobuf")
					payload, _ := proto.Marshal(tt.respProto)
					_, _ = w.Write(payload)
				}
			}))
			t.Cleanup(ts.Close)

			client, err := gitter.NewClient(ts.URL, nil)
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			resp, err := client.GetTags(context.Background(), tt.repoURL)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("GetTags() error = %v, wantErr = %v", err, tt.wantErr)
				}

				return
			}
			if err != nil {
				t.Fatalf("unexpected GetTags() error: %v", err)
			}

			if diff := cmp.Diff(tt.wantResp, resp, protocmp.Transform()); diff != "" {
				t.Errorf("GetTags() response mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGetAffectedCommits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		req        *pb.AffectedCommitsRequest
		statusCode int
		respProto  *pb.AffectedCommitsResponse
		wantResp   *pb.AffectedCommitsResponse
		wantErr    error
	}{
		{
			name: "success",
			req: &pb.AffectedCommitsRequest{
				Url: "https://github.com/google/oss-fuzz-vulns.git",
				Events: []*pb.Event{
					{EventType: pb.EventType_INTRODUCED, Hash: "3350c55f9525cb83fc3e0b61bde076433c2da8dc"},
					{EventType: pb.EventType_FIXED, Hash: "8920ed8e47c660a0c20c28cb1004a600780c5b59"},
				},
			},
			statusCode: http.StatusOK,
			respProto: &pb.AffectedCommitsResponse{
				Commits: []*pb.Commit{
					{Hash: hexDecode(t, "3350c55f9525cb83fc3e0b61bde076433c2da8dc")},
				},
			},
			wantResp: &pb.AffectedCommitsResponse{
				Commits: []*pb.Commit{
					{Hash: hexDecode(t, "3350c55f9525cb83fc3e0b61bde076433c2da8dc")},
				},
			},
		},
		{
			name: "bad request error mapping",
			req: &pb.AffectedCommitsRequest{
				Url: "https://github.com/google/oss-fuzz-vulns.git",
			},
			statusCode: http.StatusBadRequest,
			wantErr:    gitter.ErrInvalidInput,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.statusCode)
				if tt.statusCode == http.StatusOK && tt.respProto != nil {
					w.Header().Set("Content-Type", "application/x-protobuf")
					payload, _ := proto.Marshal(tt.respProto)
					_, _ = w.Write(payload)
				}
			}))
			t.Cleanup(ts.Close)

			client, err := gitter.NewClient(ts.URL, nil)
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			resp, err := client.GetAffectedCommits(context.Background(), tt.req)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("GetAffectedCommits() error = %v, wantErr = %v", err, tt.wantErr)
				}

				return
			}
			if err != nil {
				t.Fatalf("unexpected GetAffectedCommits() error: %v", err)
			}

			if diff := cmp.Diff(tt.wantResp, resp, protocmp.Transform()); diff != "" {
				t.Errorf("GetAffectedCommits() response mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGetFileDiffs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		req        *pb.FileDiffsRequest
		statusCode int
		respProto  *pb.FileDiffsResponse
		wantResp   *pb.FileDiffsResponse
		wantErr    error
	}{
		{
			name: "success",
			req: &pb.FileDiffsRequest{
				Url:              "https://github.com/oliverchang/osv-test.git",
				LastSyncedCommit: "b1c95a196f22d06fcf80df8c6691cd113d8fefff",
			},
			statusCode: http.StatusOK,
			respProto: &pb.FileDiffsResponse{
				LatestCommit: "b9b3fd4732695b83c3068b7b6a14bb372ec31f98",
				Changes: []*pb.FileChange{
					{ToPath: "branch"},
				},
			},
			wantResp: &pb.FileDiffsResponse{
				LatestCommit: "b9b3fd4732695b83c3068b7b6a14bb372ec31f98",
				Changes: []*pb.FileChange{
					{ToPath: "branch"},
				},
			},
		},
		{
			name: "error mapping",
			req: &pb.FileDiffsRequest{
				Url: "https://github.com/google/this-repo-does-not-exist-12345.git",
			},
			statusCode: http.StatusForbidden,
			wantErr:    gitter.ErrRepoInaccessible,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.statusCode)
				if tt.statusCode == http.StatusOK && tt.respProto != nil {
					w.Header().Set("Content-Type", "application/x-protobuf")
					payload, _ := proto.Marshal(tt.respProto)
					_, _ = w.Write(payload)
				}
			}))
			t.Cleanup(ts.Close)

			client, err := gitter.NewClient(ts.URL, nil)
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			resp, err := client.GetFileDiffs(context.Background(), tt.req)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("GetFileDiffs() error = %v, wantErr = %v", err, tt.wantErr)
				}

				return
			}
			if err != nil {
				t.Fatalf("unexpected GetFileDiffs() error: %v", err)
			}

			if diff := cmp.Diff(tt.wantResp, resp, protocmp.Transform()); diff != "" {
				t.Errorf("GetFileDiffs() response mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGetFileContent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		req        *pb.FileContentRequest
		statusCode int
		respProto  *pb.FileContentResponse
		wantResp   *pb.FileContentResponse
		wantErr    error
	}{
		{
			name: "success",
			req: &pb.FileContentRequest{
				Url:    "https://github.com/oliverchang/osv-test.git",
				Commit: "b9b3fd4732695b83c3068b7b6a14bb372ec31f98",
				Path:   "abc",
			},
			statusCode: http.StatusOK,
			respProto: &pb.FileContentResponse{
				Content: []byte("abcd\n"),
			},
			wantResp: &pb.FileContentResponse{
				Content: []byte("abcd\n"),
			},
		},
		{
			name: "not found error mapping",
			req: &pb.FileContentRequest{
				Url:    "https://github.com/oliverchang/osv-test.git",
				Commit: "b9b3fd4732695b83c3068b7b6a14bb372ec31f98",
				Path:   "nonexistent",
			},
			statusCode: http.StatusNotFound,
			wantErr:    gitter.ErrRepoNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.statusCode)
				if tt.statusCode == http.StatusOK && tt.respProto != nil {
					w.Header().Set("Content-Type", "application/x-protobuf")
					payload, _ := proto.Marshal(tt.respProto)
					_, _ = w.Write(payload)
				}
			}))
			t.Cleanup(ts.Close)

			client, err := gitter.NewClient(ts.URL, nil)
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			resp, err := client.GetFileContent(context.Background(), tt.req)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("GetFileContent() error = %v, wantErr = %v", err, tt.wantErr)
				}

				return
			}
			if err != nil {
				t.Fatalf("unexpected GetFileContent() error: %v", err)
			}

			if diff := cmp.Diff(tt.wantResp, resp, protocmp.Transform()); diff != "" {
				t.Errorf("GetFileContent() response mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
