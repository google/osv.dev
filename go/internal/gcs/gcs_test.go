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

package gcs

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"cloud.google.com/go/storage"
)

func TestBuildPartitionQueries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		globalPrefix      string
		breakdownPrefixes []string
		wantQueries       []*storage.Query
	}{
		{
			name:              "empty breakdowns",
			globalPrefix:      "all/pb/",
			breakdownPrefixes: nil,
			wantQueries: []*storage.Query{
				{Prefix: "all/pb/"},
			},
		},
		{
			name:              "single breakdown",
			globalPrefix:      "all/pb",
			breakdownPrefixes: []string{"CVE-"},
			wantQueries: []*storage.Query{
				{Prefix: "all/pb/", EndOffset: "all/pb/CVE-"},
				{Prefix: "all/pb/", StartOffset: "all/pb/CVE-"},
			},
		},
		{
			name:              "multiple breakdowns out of order",
			globalPrefix:      "all/pb/",
			breakdownPrefixes: []string{"GO-", "CVE-", "GHSA-"},
			wantQueries: []*storage.Query{
				{Prefix: "all/pb/", EndOffset: "all/pb/CVE-"},
				{Prefix: "all/pb/", StartOffset: "all/pb/CVE-", EndOffset: "all/pb/GHSA-"},
				{Prefix: "all/pb/", StartOffset: "all/pb/GHSA-", EndOffset: "all/pb/GO-"},
				{Prefix: "all/pb/", StartOffset: "all/pb/GO-"},
			},
		},
		{
			name:              "empty global prefix",
			globalPrefix:      "",
			breakdownPrefixes: []string{"B-", "A-"},
			wantQueries: []*storage.Query{
				{Prefix: "", EndOffset: "A-"},
				{Prefix: "", StartOffset: "A-", EndOffset: "B-"},
				{Prefix: "", StartOffset: "B-"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := buildPartitionQueries(tt.globalPrefix, tt.breakdownPrefixes)
			opts := cmpopts.IgnoreUnexported(storage.Query{})
			if diff := cmp.Diff(tt.wantQueries, got, opts); diff != "" {
				t.Errorf("buildPartitionQueries() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
