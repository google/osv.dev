package osv

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"osv-detector/pkg/lockfile"
)

const (
	// QueryEndpoint is the URL for posting queries to OSV.
	QueryEndpoint = "https://api-staging.osv.dev/v1/querybatch"
	// QueryEndpoint = "http://127.0.0.1:8080/v1/querybatch"
	// BaseVulnerabilityURL is the base URL for detailed vulnerability views.
	BaseVulnerabilityURL = "https://osv.dev/vulnerability/"
)

// Package represents a package identifier for OSV.
type Package struct {
	PURL      string `json:"purl,omitempty"`
	Name      string `json:"name,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
}

// Query represents a query to OSV.
type Query struct {
	Commit  string  `json:"commit,omitempty"`
	Package Package `json:"package,omitempty"`
}

// BatchedQuery represents a batched query to OSV.
type BatchedQuery struct {
	Queries []*Query `json:"queries"`
}

// Response represents a (simplified) response from OSV.
type Response struct {
	Vulns []struct {
		ID string `json:"id"`
	} `json:"vulns"`
}

// BatchedResponse represents a batched response from OSV.
type BatchedResponse struct {
	Results []Response `json:"results"`
}

// MakeCommitRequest makes a commit hash request.
func MakeCommitRequest(commit string) *Query {
	return &Query{
		Commit: commit,
	}
}

// MakePURLRequest makes a PURL request.
func MakePURLRequest(purl string) *Query {
	return &Query{
		Package: Package{
			PURL: purl,
		},
	}
}

func MakePkgDetailsRequest(pkgDetails lockfile.PackageDetails) *Query {
	return &Query{
		Package: Package{
			Name:      pkgDetails.Name,
			Ecosystem: string(pkgDetails.Ecosystem),
		},
	}
}

// From: https://stackoverflow.com/a/72408490
func chunkBy[T any](items []T, chunkSize int) [][]T {
	var _chunks = make([][]T, 0, (len(items)/chunkSize)+1)
	for chunkSize < len(items) {
		items, _chunks = items[chunkSize:], append(_chunks, items[0:chunkSize:chunkSize])
	}
	return append(_chunks, items)
}

func MakeRequest(request BatchedQuery) (*BatchedResponse, error) {

	// API has a limit of 1000 bulk query per request
	queryChunks := chunkBy(request.Queries, 990)
	var totalOsvResp BatchedResponse

	for _, queries := range queryChunks {
		requestBytes, err := json.Marshal(BatchedQuery{Queries: queries})
		if err != nil {
			return nil, err
		}
		requestBuf := bytes.NewBuffer(requestBytes)

		resp, err := http.Post(QueryEndpoint, "application/json", requestBuf)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			// TODO(rexpan): Better error handling
			log.Fatalf("Server response error")
		}

		var osvResp BatchedResponse
		decoder := json.NewDecoder(resp.Body)
		err = decoder.Decode(&osvResp)
		if err != nil {
			return nil, err
		}

		totalOsvResp.Results = append(totalOsvResp.Results, osvResp.Results...)
	}

	return &totalOsvResp, nil
}
