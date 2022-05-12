package osv

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
)

const (
	// QueryEndpoint is the URL for posting queries to OSV.
	QueryEndpoint = "https://api-staging.osv.dev/v1/querybatch"
	// BaseVulnerabilityURL is the base URL for detailed vulnerability views.
	BaseVulnerabilityURL = "https://osv.dev/vulnerability/"
)

// Package represents a package identifier for OSV.
type Package struct {
	PURL string `json:"purl"`
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

func MakeRequest(request BatchedQuery) (*BatchedResponse, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	requestBuf := bytes.NewBuffer(requestBytes)

	resp, err := http.Post(QueryEndpoint, "application/json", requestBuf)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var osvResp BatchedResponse
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&osvResp)
	if err != nil {
		return nil, err
	}

	return &osvResp, nil
}
