package storage

import (
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv.dev/docker/indexer/stages/preparation"
	"github.com/google/osv.dev/docker/indexer/stages/processing"
)

func getFileResults(t *testing.T, count int) []*processing.FileResult {
	t.Helper()
	var r []*processing.FileResult
	for i := 0; i < count; i++ {
		r = append(r, &processing.FileResult{
			Path: strconv.Itoa(i),
			Hash: []byte{0x42, 0x42},
		})
	}
	return r
}

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
		Pages:        pages,
	}
}

func TestNewDoc(t *testing.T) {
	for _, tc := range []struct {
		repoInfo          *preparation.Result
		fileResults       []*processing.FileResult
		wantDoc           *document
		expectedResultLen int
	}{
		{
			repoInfo:          getRepoInfo(t),
			fileResults:       getFileResults(t, 1),
			wantDoc:           getDoc(t, 1),
			expectedResultLen: 1,
		},
		{
			repoInfo:          getRepoInfo(t),
			fileResults:       getFileResults(t, 2),
			wantDoc:           getDoc(t, 1),
			expectedResultLen: 1,
		},
		{
			repoInfo:          getRepoInfo(t),
			fileResults:       getFileResults(t, 1000),
			wantDoc:           getDoc(t, 1),
			expectedResultLen: 1,
		},
		{
			repoInfo:          getRepoInfo(t),
			fileResults:       getFileResults(t, 1001),
			wantDoc:           getDoc(t, 2),
			expectedResultLen: 2,
		},
		{
			repoInfo:          getRepoInfo(t),
			fileResults:       getFileResults(t, 2001),
			wantDoc:           getDoc(t, 3),
			expectedResultLen: 3,
		},
	} {
		doc, r := newDoc(tc.repoInfo, "MD5", tc.fileResults)
		if diff := cmp.Diff(tc.wantDoc, doc); diff != "" {
			t.Errorf("newDoc() returned an unexpected document diff (-want, +got):\n%s", diff)
		}
		if len(r) != tc.expectedResultLen {
			t.Errorf("expected result length %d doesn't match %d", tc.expectedResultLen, len(r))
		}

	}
}
