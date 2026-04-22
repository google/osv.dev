package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/google/apitester/internal/jsonreplace"
	"github.com/google/apitester/internal/vcr"
	"github.com/tidwall/gjson"
	"github.com/tidwall/pretty"
	"github.com/tidwall/sjson"
)

var (
	replaceModifiedTimeFunc = func(toReplace gjson.Result) any {
		tim, err := time.Parse(time.RFC3339, toReplace.String())

		if err != nil {
			return fmt.Sprintf("<invalid date: %s>", err)
		}

		return fmt.Sprintf("<RFC3339 date with the year %d>", tim.Year())
	}
)

func jsonReplaceRules(t *testing.T, resp *http.Response) []jsonreplace.Rule {
	t.Helper()

	if resp.Request.URL.Path == "/v1/querybatch" {
		return []jsonreplace.Rule{
			{
				Path:        "results.#.vulns.#.modified",
				ReplaceFunc: replaceModifiedTimeFunc,
			},
		}
	}

	if resp.Request.URL.Path != "/v1/query" || strings.Contains(t.Name(), "/Invalid") {
		return nil
	}

	return []jsonreplace.Rule{
		{
			Path:        "vulns.#.modified",
			ReplaceFunc: replaceModifiedTimeFunc,
		},
		{
			Path: "vulns.#.affected.#.database_specific",
			ReplaceFunc: func(_ gjson.Result) any {
				return "<Any value>"
			},
		},
		{
			Path: "vulns.#.affected.#.ranges.#.database_specific",
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

func normalizeJSONBody(t *testing.T, reqBody []byte, resp *http.Response) string {
	t.Helper()

	body, err := io.ReadAll(resp.Body)

	if err != nil {
		t.Fatal(err)
	}

	body = jsonreplace.DoBytes(t, body, jsonReplaceRules(t, resp))

	switch resp.Request.URL.Path {
	case "/v1/query":
		if len(reqBody) > 0 {
			res, err := sjson.SetRawBytes(body, "query", reqBody)
			if err == nil {
				body = res
			}
		}
		if !gjson.GetBytes(body, "vulns").Exists() && !gjson.GetBytes(body, "code").Exists() {
			res, err := sjson.SetRawBytes(body, "vulns", []byte("[]"))
			if err == nil {
				body = res
			}
		} else if vulns := gjson.GetBytes(body, "vulns"); vulns.Exists() {
			body, _ = sjson.DeleteBytes(body, "vulns")
			body, _ = sjson.SetRawBytes(body, "vulns", []byte(vulns.Raw))
		}
	case "/v1/querybatch":
		queries := gjson.GetBytes(reqBody, "queries")
		results := gjson.GetBytes(body, "results")
		if queries.IsArray() && results.IsArray() {
			for i, query := range queries.Array() {
				if i < len(results.Array()) {
					res, err := sjson.SetRawBytes(body, fmt.Sprintf("results.%d.query", i), []byte(query.Raw))
					if err == nil {
						body = res
					}
					if !gjson.GetBytes(body, fmt.Sprintf("results.%d.vulns", i)).Exists() && !gjson.GetBytes(body, "code").Exists() {
						res, err := sjson.SetRawBytes(body, fmt.Sprintf("results.%d.vulns", i), []byte("[]"))
						if err == nil {
							body = res
						}
					} else if vulns := gjson.GetBytes(body, fmt.Sprintf("results.%d.vulns", i)); vulns.Exists() {
						body, _ = sjson.DeleteBytes(body, fmt.Sprintf("results.%d.vulns", i))
						body, _ = sjson.SetRawBytes(body, fmt.Sprintf("results.%d.vulns", i), []byte(vulns.Raw))
					}
				}
			}
		}
	}

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

					reqBody := []byte(interaction.Request.Body)
					resp := vcr.Play(t, interaction)
					body := normalizeJSONBody(t, reqBody, resp)

					resp.Body.Close()

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
