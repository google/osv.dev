package vcr

import (
	"net/http"
	"os"
	"strings"
	"testing"

	"gopkg.in/dnaeon/go-vcr.v4/pkg/cassette"
)

func DetermineInteractionName(interaction *cassette.Interaction) string {
	return interaction.Request.Headers.Get("X-Test-Name")
}

func fetchAPIBaseURL() string {
	v, ok := os.LookupEnv("OSV_API_BASE_URL")

	if !ok {
		v = "localhost:8080"
	}

	return v
}

func Play(t *testing.T, interaction *cassette.Interaction) *http.Response {
	t.Helper()

	req, err := interaction.GetHTTPRequest()

	if err != nil {
		t.Fatal(err)
	}

	req.URL.Host = fetchAPIBaseURL()
	req.Header.Set("User-Agent", "osv.dev/apitester")
	req.ContentLength = -1
	baseHost, _, _ := strings.Cut(req.URL.Host, ":")

	if baseHost == "localhost" || baseHost == "127.0.0.1" {
		req.URL.Scheme = "http"
	}

	resp, err := http.DefaultClient.Do(req)

	if err != nil {
		t.Fatal(err)
	}

	return resp
}
