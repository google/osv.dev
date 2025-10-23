package main

import (
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/tidwall/pretty"
	"gopkg.in/dnaeon/go-vcr.v4/pkg/cassette"
)

func LoadCassettes(t *testing.T) []*cassette.Cassette {
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

func determineCassetteName(cas *cassette.Cassette) string {
	return "cassette_" + path.Base(cas.Name)
}

func determineInteractionName(interaction *cassette.Interaction) string {
	return interaction.Request.Headers.Get("X-Test-Name")
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)

	if err != nil {
		t.Fatal(err)
	}

	return string(pretty.Pretty(body))
}

func PlayInteraction(t *testing.T, interaction *cassette.Interaction) *http.Response {
	t.Helper()

	req, err := interaction.GetHTTPRequest()

	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.DefaultClient.Do(req)

	if err != nil {
		t.Fatal(err)
	}

	return resp
}
