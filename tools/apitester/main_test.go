package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/tidwall/gjson"
	"github.com/tidwall/pretty"
)

func jsonReplaceRules(t *testing.T, resp *http.Response) []JSONReplaceRule {
	t.Helper()

	if strings.Contains(t.Name(), "/Invalid") {
		return nil
	}

	if resp.Request.URL.Path == "/v1/query" {
		return []JSONReplaceRule{
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
		}
	}

	if resp.Request.URL.Path == "v1/querybulk" {
		return []JSONReplaceRule{}
	}

	return []JSONReplaceRule{}
}

func normalizeJSONBody(t *testing.T, resp *http.Response) string {
	t.Helper()

	body := readBody(t, resp)

	for _, rule := range jsonReplaceRules(t, resp) {
		body = replaceJSONInput(t, body, rule.Path, rule.ReplaceFunc)
	}

	return string(pretty.Pretty(body))
}

func Test(t *testing.T) {
	t.Parallel()

	cassettes := LoadCassettes(t)

	for _, cas := range cassettes {
		t.Run(determineCassetteName(cas), func(t *testing.T) {
			t.Parallel()
			for _, interaction := range cas.Interactions {
				t.Run(determineInteractionName(interaction), func(t *testing.T) {
					t.Parallel()

					resp := PlayInteraction(t, interaction)
					body := normalizeJSONBody(t, resp)

					snaps.
						WithConfig(snaps.Filename(determineCassetteName(cas))).
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
