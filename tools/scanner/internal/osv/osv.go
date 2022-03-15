package osv

import (
	"bytes"
	"encoding/json"
	"net/http"
)

const (
	// QueryEndpoint is the URL for posting queries to OSV.
	QueryEndpoint = "https://api.osv.dev/v1/query"
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

// Response represents a (simplified) response from OSV.
type Response struct {
	Vulns []struct {
		ID string `json:"id"`
	} `json:"vulns"`
}

// MakeCommitRequest makes a commit hash request.
func MakeCommitRequest(commit string) (*Response, error) {
	request := Query{
		Commit: commit,
	}
	return makeRequest(request)
}

// MakePURLRequest makes a PURL request.
func MakePURLRequest(purl string) (*Response, error) {
	request := Query{
		Package: Package{
			PURL: purl,
		},
	}
	return makeRequest(request)
}

func makeRequest(request Query) (*Response, error) {
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

	var osvResp Response
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&osvResp)
	if err != nil {
		return nil, err
	}

	return &osvResp, nil
}
