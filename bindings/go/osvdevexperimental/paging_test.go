package osvdevexperimental

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/testing/protocmp"
	"osv.dev/bindings/go/api"
)

type mockOSVClient struct {
	queryResponses     map[string]*api.VulnerabilityList
	batchQueryReponses map[string]*api.BatchVulnerabilityList
}

func (m *mockOSVClient) Query(_ context.Context, query *api.Query) (*api.VulnerabilityList, error) {
	key := query.GetPageToken()
	if key == "" {
		key = "first"
	}
	resp, ok := m.queryResponses[key]
	if !ok {
		return nil, errors.New("no response for query")
	}

	return resp, nil
}

func (m *mockOSVClient) QueryBatch(_ context.Context, queries []*api.Query) (*api.BatchVulnerabilityList, error) {
	// For simplicity, we'll just use the first query's page token to determine the response.
	key := ""
	if len(queries) > 0 {
		key = queries[0].GetPageToken()
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
		queryResponses: map[string]*api.VulnerabilityList{
			"first": {
				Vulns: []*osvschema.Vulnerability{
					{Id: "VULN-1"},
				},
				NextPageToken: "page2",
			},
			"page2": {
				Vulns: []*osvschema.Vulnerability{
					{Id: "VULN-2"},
				},
				NextPageToken: "page3",
			},
			"page3": {
				Vulns: []*osvschema.Vulnerability{
					{Id: "VULN-3"},
				},
			},
		},
	}

	query := &api.Query{}
	resp, err := QueryPaging(context.Background(), mockClient, query)
	if err != nil {
		t.Fatalf("QueryPaging failed: %v", err)
	}

	expectedVulns := []*osvschema.Vulnerability{
		{Id: "VULN-1"},
		{Id: "VULN-2"},
		{Id: "VULN-3"},
	}

	if diff := cmp.Diff(expectedVulns, resp.GetVulns(), protocmp.Transform()); diff != "" {
		t.Errorf("QueryPaging returned unexpected vulns (-want +got):\n%s", diff)
	}

	if resp.GetNextPageToken() != "" {
		t.Errorf("Expected empty NextPageToken, got %s", resp.GetNextPageToken())
	}
}

func TestBatchQueryPaging(t *testing.T) {
	mockClient := &mockOSVClient{
		batchQueryReponses: map[string]*api.BatchVulnerabilityList{
			"first": {
				Results: []*api.VulnerabilityList{
					{ // Query 1, Page 1
						Vulns:         []*osvschema.Vulnerability{{Id: "Q1-VULN-1"}},
						NextPageToken: "q1page2",
					},
					{ // Query 2, Page 1
						Vulns: []*osvschema.Vulnerability{{Id: "Q2-VULN-1"}},
					},
				},
			},
			"q1page2": {
				Results: []*api.VulnerabilityList{
					{ // Query 1, Page 2
						Vulns: []*osvschema.Vulnerability{{Id: "Q1-VULN-2"}},
					},
				},
			},
		},
	}

	queries := []*api.Query{
		{
			Param: &api.Query_Commit{
				Commit: "q1",
			},
		},
		{
			Param: &api.Query_Commit{
				Commit: "q2",
			},
		},
	}

	resp, err := BatchQueryPaging(context.Background(), mockClient, queries)
	if err != nil {
		t.Fatalf("BatchQueryPaging failed: %v", err)
	}

	expectedResponses := []*api.VulnerabilityList{
		{
			Vulns: []*osvschema.Vulnerability{
				{Id: "Q1-VULN-1"},
				{Id: "Q1-VULN-2"},
			},
		},
		{
			Vulns: []*osvschema.Vulnerability{
				{Id: "Q2-VULN-1"},
			},
		},
	}

	if diff := cmp.Diff(expectedResponses, resp.GetResults(), protocmp.Transform()); diff != "" {
		t.Errorf("BatchQueryPaging returned unexpected results (-want +got):\n%s", diff)
	}
}
