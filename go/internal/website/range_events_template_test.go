package website

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"strings"
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"golang.org/x/net/html"
	"google.golang.org/protobuf/encoding/protojson"
)

// Render the complete content template to exercise both affected-package layouts.
func TestRangeEventsTemplate(t *testing.T) {
	tmpl, err := template.New("vulnerability").Funcs(template.FuncMap{
		"hasPrefix": strings.HasPrefix,
		"add":       func(a, b int) int { return a + b },
		"sub":       func(a, b int) int { return a - b },
	}).ParseFiles("../../../website/frontend3/src/templates/vulnerability.html")
	if err != nil {
		t.Fatal(err)
	}

	for _, packageCount := range []int{1, 6} {
		for _, eventCount := range []int{0, 1, 6, 7, 20} {
			t.Run(fmt.Sprintf("packages=%d/events=%d", packageCount, eventCount), func(t *testing.T) {
				events := make([]map[string]string, 0, eventCount)
				for i := range eventCount {
					eventType := []string{"introduced", "fixed", "last_affected", "limit"}[i%4]
					events = append(events, map[string]string{eventType: fmt.Sprintf("event-%d", i)})
				}
				affected := make([]any, 0, packageCount)
				for i := range packageCount {
					affected = append(affected, map[string]any{
						"package": map[string]string{"ecosystem": "PyPI", "name": fmt.Sprintf("package-%d", i)},
						"ranges": []any{
							map[string]any{"type": "ECOSYSTEM", "events": events},
							// A short range in the same package must remain independent.
							map[string]any{"type": "GIT", "repo": "https://github.com/example/repo", "events": []any{
								map[string]string{"introduced": "0"},
								map[string]string{"fixed": "abcdef"},
							}},
						},
					})
				}
				data, err := json.Marshal(map[string]any{"id": "TEST-6064", "affected": affected})
				if err != nil {
					t.Fatal(err)
				}
				vuln := &osvschema.Vulnerability{}
				if err := protojson.Unmarshal(data, vuln); err != nil {
					t.Fatal(err)
				}
				page := VulnerabilityPageData{Vulnerability: vuln}
				if page.ShouldCollapse() != (packageCount == 6) {
					t.Fatal("fixture does not exercise the expected package layout")
				}
				var output bytes.Buffer
				if err := tmpl.ExecuteTemplate(&output, "content", page); err != nil {
					t.Fatal(err)
				}
				doc, err := html.Parse(strings.NewReader(output.String()))
				if err != nil {
					t.Fatal(err)
				}
				visible, hidden, controls := 0, 0, 0
				var visit func(*html.Node, bool)
				visit = func(n *html.Node, collapsed bool) {
					for _, attr := range n.Attr {
						if attr.Key != "class" {
							continue
						}
						if attr.Val == "events-section" {
							controls++
							collapsed = true
							for _, attr := range n.Attr {
								if attr.Key == "open" {
									t.Error("event lists should start collapsed")
								}
							}
						}
						if strings.Contains(attr.Val, "version-value") {
							if collapsed {
								hidden++
							} else {
								visible++
							}
						}
					}
					for c := n.FirstChild; c != nil; c = c.NextSibling {
						visit(c, collapsed)
					}
				}
				visit(doc, false)
				wantControls := 0
				if eventCount > 6 {
					wantControls = packageCount
					label := fmt.Sprintf("Show %d more events", eventCount-6)
					if eventCount == 7 {
						label = "Show 1 more event"
					}
					if strings.Count(output.String(), label+"</span>") != packageCount {
						t.Errorf("missing remaining-event label %q", label)
					}
				}
				if controls != wantControls || visible != packageCount*(min(eventCount, 6)+2) || hidden != packageCount*max(eventCount-6, 0) {
					t.Errorf("controls=%d, visible=%d, hidden=%d for %d events in %d packages", controls, visible, hidden, eventCount, packageCount)
				}
				for i := range eventCount {
					if strings.Count(output.String(), fmt.Sprintf("event-%d\n", i)) != packageCount {
						t.Errorf("event-%d missing or duplicated", i)
					}
				}
				if strings.Count(output.String(), `href="https://github.com/example/repo/commit/abcdef"`) != packageCount || strings.Count(output.String(), `class="tooltiptext"`) != packageCount {
					t.Error("commit links or unknown-introduced tooltips were lost")
				}
			})
		}
	}
}
