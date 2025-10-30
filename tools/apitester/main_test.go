package main

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/google/apitester/internal/jsonreplace"
	"github.com/google/apitester/internal/vcr"
	"github.com/tidwall/gjson"
	"github.com/tidwall/pretty"
)

func jsonReplaceRules(t *testing.T, resp *http.Response) []jsonreplace.Rule {
	t.Helper()

	if resp.Request.URL.Path != "/v1/query" || strings.Contains(t.Name(), "/Invalid") {
		return nil
	}

	return []jsonreplace.Rule{
		{
			Path: "vulns.#.affected.#.database_specific",
			ReplaceFunc: func(_ gjson.Result) any {
				return "<Any value>"
			},
		},
		{
			Path: "vulns.#.database_specific",
			ReplaceFunc: func(_ gjson.Result) any {
				return "<Any value>"
			},
		},
		{
			Path: "vulns.#.affected.#.versions",
			ReplaceFunc: func(toReplace gjson.Result) any {
				if toReplace.IsArray() {
					return len(toReplace.Array())
				}

				return 0
			},
		},
	}
}

func normalizeJSONBody(t *testing.T, resp *http.Response) string {
	t.Helper()

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)

	if err != nil {
		t.Fatal(err)
	}

	body = jsonreplace.DoBytes(t, body, jsonReplaceRules(t, resp))

	return string(pretty.Pretty(body))
}

func Test(t *testing.T) {
	t.Parallel()

	cassettes := vcr.Load(t)

	for _, cas := range cassettes {
		t.Run(vcr.DetermineCassetteName(cas), func(t *testing.T) {
			t.Parallel()
			for _, interaction := range cas.Interactions {
				t.Run(vcr.DetermineInteractionName(interaction), func(t *testing.T) {
					t.Parallel()

					resp := vcr.Play(t, interaction)
					body := normalizeJSONBody(t, resp)

					snaps.
						WithConfig(snaps.Filename(vcr.DetermineCassetteName(cas))).
						MatchSnapshot(t, body)
				})
			}
		})
	}
}

func Test_Example(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Name  string
		Cases []string
	}{
		{Name: "classic", Cases: []string{"world", "sunshine"}},
		{Name: "planets", Cases: []string{"earth", "mars"}},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			for _, ttt := range tt.Cases {
				t.Run(ttt, func(t *testing.T) {
					t.Parallel()

					snaps.MatchSnapshot(t, "hello "+ttt)
				})
			}
		})
	}
}
