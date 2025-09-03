package osvdevexperimental

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"osv.dev/bindings/go/osvdev"
)

type mockOSVClient struct {
	queryResponses     map[string]*osvdev.Response
	batchQueryReponses map[string]*osvdev.BatchedResponse
}

func (m *mockOSVClient) Query(_ context.Context, query *osvdev.Query) (*osvdev.Response, error) {
	key := query.PageToken
	if key == "" {
		key = "first"
	}
	resp, ok := m.queryResponses[key]
	if !ok {
		return nil, errors.New("no response for query")
	}

	return resp, nil
}

func (m *mockOSVClient) QueryBatch(_ context.Context, queries []*osvdev.Query) (*osvdev.BatchedResponse, error) {
	// For simplicity, we'll just use the first query's page token to determine the response.
	key := ""
	if len(queries) > 0 {
		key = queries[0].PageToken
	}
	if key == "" {
		key = "first"
	}

	resp, ok := m.batchQueryReponses[key]
	if !ok {
		return nil, errors.New("no response for batch query")
	}

	return resp, nil
}

func TestQueryPaging(t *testing.T) {
	mockClient := &mockOSVClient{
		queryResponses: map[string]*osvdev.Response{
			"first": {
				Vulns: []osvschema.Vulnerability{
					{ID: "VULN-1"},
				},
				NextPageToken: "page2",
			},
			"page2": {
				Vulns: []osvschema.Vulnerability{
					{ID: "VULN-2"},
				},
				NextPageToken: "page3",
			},
			"page3": {
				Vulns: []osvschema.Vulnerability{
					{ID: "VULN-3"},
				},
			},
		},
	}

	query := &osvdev.Query{}
	resp, err := QueryPaging(context.Background(), mockClient, query)
	if err != nil {
		t.Fatalf("QueryPaging failed: %v", err)
	}

	expectedVulns := []osvschema.Vulnerability{
		{ID: "VULN-1"},
		{ID: "VULN-2"},
		{ID: "VULN-3"},
	}

	if diff := cmp.Diff(expectedVulns, resp.Vulns); diff != "" {
		t.Errorf("QueryPaging returned unexpected vulns (-want +got):\n%s", diff)
	}

	if resp.NextPageToken != "" {
		t.Errorf("Expected empty NextPageToken, got %s", resp.NextPageToken)
	}
}

func TestBatchQueryPaging(t *testing.T) {
	mockClient := &mockOSVClient{
		batchQueryReponses: map[string]*osvdev.BatchedResponse{
			"first": {
				Results: []osvdev.MinimalResponse{
					{ // Query 1, Page 1
						Vulns:         []osvdev.MinimalVulnerability{{ID: "Q1-VULN-1"}},
						NextPageToken: "q1page2",
					},
					{ // Query 2, Page 1
						Vulns: []osvdev.MinimalVulnerability{{ID: "Q2-VULN-1"}},
					},
				},
			},
			"q1page2": {
				Results: []osvdev.MinimalResponse{
					{ // Query 1, Page 2
						Vulns: []osvdev.MinimalVulnerability{{ID: "Q1-VULN-2"}},
					},
				},
			},
		},
	}

	queries := []*osvdev.Query{
		{Commit: "q1"},
		{Commit: "q2"},
	}

	resp, err := BatchQueryPaging(context.Background(), mockClient, queries)
	if err != nil {
		t.Fatalf("BatchQueryPaging failed: %v", err)
	}

	expectedResponses := []osvdev.MinimalResponse{
		{
			Vulns: []osvdev.MinimalVulnerability{
				{ID: "Q1-VULN-1"},
				{ID: "Q1-VULN-2"},
			},
		},
		{
			Vulns: []osvdev.MinimalVulnerability{
				{ID: "Q2-VULN-1"},
			},
		},
	}

	if diff := cmp.Diff(expectedResponses, resp.Results, cmp.AllowUnexported(osvdev.Response{})); diff != "" {
		t.Errorf("BatchQueryPaging returned unexpected results (-want +got):\n%s", diff)
	}
}
