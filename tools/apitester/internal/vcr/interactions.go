package vcr

import (
	"net/http"
	"testing"

	"gopkg.in/dnaeon/go-vcr.v4/pkg/cassette"
)

func DetermineInteractionName(interaction *cassette.Interaction) string {
	return interaction.Request.Headers.Get("X-Test-Name")
}

func Play(t *testing.T, interaction *cassette.Interaction) *http.Response {
	t.Helper()

	req, err := interaction.GetHTTPRequest()

	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("User-Agent", "osv.dev/apitester")
	req.ContentLength = -1

	resp, err := http.DefaultClient.Do(req)

	if err != nil {
		t.Fatal(err)
	}

	return resp
}
