package website

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"text/template"

	"github.com/google/osv.dev/go/logger"
	"github.com/nikolalohinski/gonja/v2"
	"github.com/nikolalohinski/gonja/v2/exec"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// humanLinkFuncs are the functions available to human_link templates
// (configured per source in source.yaml), in addition to the text/template builtins.
var humanLinkFuncs = template.FuncMap{
	// field splits s on sep and returns the n-th part (0-indexed).
	// e.g. {{ .ID | field "-" 1 }} on "JLSEC-2025-1" returns "2025".
	"field": func(sep string, n int, s string) (string, error) {
		parts := strings.Split(s, sep)
		if n < 0 || n >= len(parts) {
			return "", fmt.Errorf("field %d out of range splitting %q on %q", n, s, sep)
		}

		return parts[n], nil
	},
	// replace replaces all occurrences of from with to in s.
	"replace": func(from, to, s string) string {
		return strings.ReplaceAll(s, from, to)
	},
	"lower": strings.ToLower,
}

// humanLinkData is the data available to human_link templates.
type humanLinkData struct {
	// ID is the vulnerability ID.
	ID string
	// Ecosystems are the ecosystems of each affected package, in order.
	Ecosystems []string
}

// parseHumanLink parses a human_link template.
func parseHumanLink(tmplStr string) (*template.Template, error) {
	return template.New("human_link").Funcs(humanLinkFuncs).Parse(tmplStr)
}

// RenderHumanLink renders a source's human_link template for the vulnerability.
// The template is a Go text/template with the data in humanLinkData and the functions in humanLinkFuncs.
// An error (e.g. a field index out of range) means no link should be shown.
func RenderHumanLink(ctx context.Context, tmplStr string, vuln *osvschema.Vulnerability) (string, error) {
	if tmplStr == "" {
		return "", nil
	}

	data := humanLinkData{
		ID:         vuln.GetId(),
		Ecosystems: make([]string, 0, len(vuln.GetAffected())),
	}
	for _, a := range vuln.GetAffected() {
		data.Ecosystems = append(data.Ecosystems, a.GetPackage().GetEcosystem())
	}

	tpl, err := parseHumanLink(tmplStr)
	if err != nil {
		// TODO(michaelkedar): Remove this fallback (and the gonja dependency) once all
		// SourceRepository human_links have been migrated from jinja to Go templates.
		logger.WarnContext(ctx, "human_link is not a valid Go template, falling back to jinja",
			slog.String("id", vuln.GetId()), slog.String("human_link", tmplStr), slog.Any("error", err))

		return renderJinjaHumanLink(tmplStr, data)
	}

	var sb strings.Builder
	if err := tpl.Execute(&sb, data); err != nil {
		return "", err
	}

	return sb.String(), nil
}

// renderJinjaHumanLink renders a legacy jinja human_link template.
func renderJinjaHumanLink(tmplStr string, data humanLinkData) (string, error) {
	tpl, err := gonja.FromString(tmplStr)
	if err != nil {
		return "", err
	}

	return tpl.ExecuteToString(exec.NewContext(map[string]any{
		"BUG_ID":     data.ID,
		"ECOSYSTEMS": data.Ecosystems,
	}))
}
