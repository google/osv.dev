/*
Copyright 2022 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package storage

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv.dev/gcp/indexer/stages/preparation"
)

func getRepoInfo(t *testing.T) *preparation.Result {
	return &preparation.Result{
		Name:   "abc",
		Commit: [20]byte{0x41, 0x41, 0x41, 0x41},
	}
}

func getDoc(t *testing.T, pages int) *document {
	return &document{
		Name:         "abc",
		Commit:       []byte{0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		FileHashType: "MD5",
	}
}

func TestNewDoc(t *testing.T) {
	for _, tc := range []struct {
		repoInfo *preparation.Result
		wantDoc  *document
	}{
		{
			repoInfo: getRepoInfo(t),
			wantDoc:  getDoc(t, 1),
		},
		{
			repoInfo: getRepoInfo(t),
			wantDoc:  getDoc(t, 1),
		},
		{
			repoInfo: getRepoInfo(t),
			wantDoc:  getDoc(t, 1),
		},
		{
			repoInfo: getRepoInfo(t),
			wantDoc:  getDoc(t, 2),
		},
		{
			repoInfo: getRepoInfo(t),
			wantDoc:  getDoc(t, 3),
		},
	} {
		doc := newDoc(tc.repoInfo, "MD5")
		if diff := cmp.Diff(tc.wantDoc, doc); diff != "" {
			t.Errorf("newDoc() returned an unexpected document diff (-want, +got):\n%s", diff)
		}
	}
}
