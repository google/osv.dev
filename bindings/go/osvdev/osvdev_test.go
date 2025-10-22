package osvdev_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"osv.dev/bindings/go/api"
	"osv.dev/bindings/go/internal/testhelper"
	"osv.dev/bindings/go/osvdev"
)

func TestOSVClient_GetVulnsByID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		id      string
		wantErr error
	}{
		{
			name: "Simple ID lookup",
			id:   "GO-2024-3333",
		},
		{
			name: "Missing ID lookup",
			id:   "GO-1000-1000",
			wantErr: testhelper.ErrContainsStr{
				Str: `client error: status="404 Not Found" body={"code":5,"message":"Bug not found."}`,
			},
		},
		{
			name: "Invalid ID",
			id:   "_--_--",
			wantErr: testhelper.ErrContainsStr{
				Str: `client error: status="404 Not Found" body={"code":5,"message":"Bug not found."}`,
			},
		},
	}
	for i := range tests {
		tt := &tests[i]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := osvdev.DefaultClient()
			c.Config.UserAgent = "osv-scanner-api-test"

			got, err := c.GetVulnByID(context.Background(), tt.id)

			if diff := cmp.Diff(tt.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("Unexpected error (-want +got):\n%s", diff)
			}

			if err != nil {
				return
			}

			if got.GetId() != tt.id {
				t.Errorf("OSVClient.GetVulnsByID() = %v, want %v", got, tt.id)
			}
		})
	}
}

func TestOSVClient_QueryBatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		queries []*api.Query
		wantIDs [][]string
		wantErr error
	}{
		{
			name: "multiple queries lookup",
			queries: []*api.Query{
				{
					Package: &osvschema.Package{
						Name:      "faker",
						Ecosystem: string(osvconstants.EcosystemNPM),
					},
					Param: &api.Query_Version{
						Version: "6.6.6",
					},
				},
				{
					Param: &api.Query_Commit{
						Commit: "60e572dbf7b4ded66b488f54773f66aaf6184321",
					},
				},
				{
					Package: &osvschema.Package{
						Name:      "abcd-definitely-does-not-exist",
						Ecosystem: string(osvconstants.EcosystemNPM),
					},
					Param: &api.Query_Version{
						Version: "1.0.0",
					},
				},
			},
			wantIDs: [][]string{
				{ // Package Query
					"GHSA-5w9c-rv96-fr7g",
				},
				{ // Commit
					"CVE-2024-2002",
					"OSV-2023-890",
				},
				// non-existent package
				{},
			},
		},
		{
			name: "multiple queries with invalid",
			queries: []*api.Query{
				{
					Package: &osvschema.Package{
						Name:      "faker",
						Ecosystem: string(osvconstants.EcosystemNPM),
					},
					Param: &api.Query_Version{
						Version: "6.6.6",
					},
				},
				{
					Package: &osvschema.Package{
						Name: "abcd-definitely-does-not-exist",
					},
				},
			},
			wantIDs: [][]string{},
			wantErr: testhelper.ErrContainsStr{
				Str: `client error: status="400 Bad Request" body={"code":3,"message":"Invalid query."}`,
			},
		},
	}

	for i := range tests {
		tt := &tests[i]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := osvdev.DefaultClient()
			c.Config.UserAgent = "osv-scanner-api-test"

			got, err := c.QueryBatch(context.Background(), tt.queries)

			if diff := cmp.Diff(tt.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("Unexpected error (-want +got):\n%s", diff)
			}

			if err != nil {
				return
			}

			gotResults := make([][]string, 0, len(got.GetResults()))
			for _, res := range got.GetResults() {
				gotVulnIDs := make([]string, 0, len(res.GetVulns()))
				for _, vuln := range res.GetVulns() {
					gotVulnIDs = append(gotVulnIDs, vuln.GetId())
				}
				gotResults = append(gotResults, gotVulnIDs)
			}

			if diff := cmp.Diff(tt.wantIDs, gotResults); diff != "" {
				t.Errorf("Unexpected vuln IDs (-want +got):\n%s", diff)
			}
		})
	}
}

func TestOSVClient_QueryBatchDeadline(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		queries []*api.Query
		wantIDs [][]string
		wantErr error
	}{
		{
			name: "linux package lookup",
			queries: []*api.Query{
				{
					Param: &api.Query_Commit{
						Commit: "60e572dbf7b4ded66b488f54773f66aaf6184321",
					},
				},
				{
					Package: &osvschema.Package{
						Name:      "linux",
						Ecosystem: "Ubuntu:22.04:LTS",
					},
					Param: &api.Query_Version{
						Version: "5.15.0-17.17",
					},
				},
				{
					Package: &osvschema.Package{
						Name:      "abcd-definitely-does-not-exist",
						Ecosystem: string(osvconstants.EcosystemNPM),
					},
					Param: &api.Query_Version{
						Version: "1.0.0",
					},
				},
			},
			wantErr: context.DeadlineExceeded,
		},
	}

	for i := range tests {
		tt := &tests[i]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := osvdev.DefaultClient()
			c.Config.UserAgent = "osv-scanner-api-test"
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Second*1))

			got, err := c.QueryBatch(ctx, tt.queries)
			cancel()
			if diff := cmp.Diff(tt.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("Unexpected error (-want +got):\n%s", diff)
			}

			if err != nil {
				return
			}

			gotResults := make([][]string, 0, len(got.GetResults()))
			for _, res := range got.GetResults() {
				gotVulnIDs := make([]string, 0, len(res.GetVulns()))
				for _, vuln := range res.GetVulns() {
					gotVulnIDs = append(gotVulnIDs, vuln.GetId())
				}
				gotResults = append(gotResults, gotVulnIDs)
			}

			if diff := cmp.Diff(tt.wantIDs, gotResults); diff != "" {
				t.Errorf("Unexpected vuln IDs (-want +got):\n%s", diff)
			}
		})
	}
}

func TestOSVClient_Query(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		query   api.Query
		wantIDs []string
		wantErr error
	}{
		{
			name: "npm Package lookup",
			query: api.Query{
				Package: &osvschema.Package{
					// Use a deleted package as it is less likely new vulns will be published for it
					Name:      "faker",
					Ecosystem: string(osvconstants.EcosystemNPM),
				},
				Param: &api.Query_Version{
					Version: "6.6.6",
				},
			},
			wantIDs: []string{
				"GHSA-5w9c-rv96-fr7g",
			},
		},
		{
			name: "commit lookup",
			query: api.Query{
				Param: &api.Query_Commit{
					Commit: "60e572dbf7b4ded66b488f54773f66aaf6184321",
				},
			},
			wantIDs: []string{
				"CVE-2024-2002",
				"OSV-2023-890",
			},
		},
		{
			name: "unknown package lookup",
			query: api.Query{
				Package: &osvschema.Package{
					Name:      "abcd-definitely-does-not-exist",
					Ecosystem: string(osvconstants.EcosystemNPM),
				},
				Param: &api.Query_Version{
					Version: "1.0.0",
				},
			},
			wantIDs: []string{},
		},
		{
			name: "invalid query",
			query: api.Query{
				Package: &osvschema.Package{
					Name: "abcd-definitely-does-not-exist",
				},
			},
			wantErr: testhelper.ErrContainsStr{
				Str: `client error: status="400 Bad Request" body={"code":3,"message":"Invalid query."}`,
			},
		},
	}
	for i := range tests {
		tt := &tests[i]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := osvdev.DefaultClient()
			c.Config.UserAgent = "osv-scanner-api-test"

			got, err := c.Query(context.Background(), &tt.query)

			if diff := cmp.Diff(tt.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("Unexpected error (-want +got):\n%s", diff)
			}

			if err != nil {
				return
			}

			gotVulnIDs := make([]string, 0, len(got.GetVulns()))
			for _, vuln := range got.GetVulns() {
				gotVulnIDs = append(gotVulnIDs, vuln.GetId())
			}

			if diff := cmp.Diff(tt.wantIDs, gotVulnIDs); diff != "" {
				t.Errorf("Unexpected vuln IDs (-want +got):\n%s", diff)
			}
		})
	}
}

func TestOSVClient_QueryDeadline(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		query   api.Query
		wantIDs []string
		wantErr error
	}{
		{
			name: "linux Package lookup",
			query: api.Query{
				Package: &osvschema.Package{
					// Use a deleted package as it is less likely new vulns will be published for it
					Name:      "linux",
					Ecosystem: "Ubuntu:22.04:LTS",
				},
				Param: &api.Query_Version{
					Version: "5.15.0-17.17",
				},
			},
			wantErr: context.DeadlineExceeded,
		},
	}
	for i := range tests {
		tt := &tests[i]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := osvdev.DefaultClient()
			c.Config.UserAgent = "osv-scanner-api-test"

			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Second*1))
			got, err := c.Query(ctx, &tt.query)
			cancel()

			if diff := cmp.Diff(tt.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("Unexpected error (-want +got):\n%s", diff)
			}

			if err != nil {
				return
			}

			gotVulnIDs := make([]string, 0, len(got.GetVulns()))
			for _, vuln := range got.GetVulns() {
				gotVulnIDs = append(gotVulnIDs, vuln.GetId())
			}

			if diff := cmp.Diff(tt.wantIDs, gotVulnIDs); diff != "" {
				t.Errorf("Unexpected vuln IDs (-want +got):\n%s", diff)
			}
		})
	}
}

func TestOSVClient_ExperimentalDetermineVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		query    api.DetermineVersionParameters
		wantPkgs []string
	}{
		{
			name: "Simple non existent package query",
			query: api.DetermineVersionParameters{
				Query: &api.VersionQuery{
					Name: "test file",
					FileHashes: []*api.FileHash{
						{
							FilePath: "test file/file",
							Hash:     []byte{},
						},
					},
				},
			},
			wantPkgs: []string{},
		},
		// TODO: Add query for an actual package, this is not added at the moment as it requires too many hashes
	}
	for i := range tests {
		tt := &tests[i]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := osvdev.DefaultClient()
			c.Config.UserAgent = "osv-scanner-api-test"

			got, err := c.ExperimentalDetermineVersion(context.Background(), &tt.query)
			if err != nil {
				t.Fatalf("Unexpected error %v", err)
			}

			gotPkgInfo := make([]string, 0, len(got.GetMatches()))
			for _, vuln := range got.GetMatches() {
				gotPkgInfo = append(gotPkgInfo, vuln.GetRepoInfo().GetAddress()+"@"+vuln.GetRepoInfo().GetVersion())
			}

			if diff := cmp.Diff(tt.wantPkgs, gotPkgInfo); diff != "" {
				t.Errorf("Unexpected vuln IDs (-want +got):\n%s", diff)
			}
		})
	}
}
