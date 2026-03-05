// Package vcr provides functions relating to go-vcr
package vcr

import (
	"os"
	"path"
	"strings"
	"testing"

	"gopkg.in/dnaeon/go-vcr.v4/pkg/cassette"
)

func DetermineCassetteName(cas *cassette.Cassette) string {
	return "cassette_" + path.Base(cas.Name)
}

func Load(t *testing.T) []*cassette.Cassette {
	t.Helper()

	files, err := os.ReadDir("./testdata/cassettes")

	if err != nil {
		t.Fatal(err)
	}

	cassettes := make([]*cassette.Cassette, 0, len(files))
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		name, _, _ := strings.Cut(file.Name(), ".")

		cas, err := cassette.Load("./testdata/cassettes/" + name)

		if err != nil {
			t.Fatal(err)
		}
		cassettes = append(cassettes, cas)
	}

	return cassettes
}
