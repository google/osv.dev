package website

import (
	"context"
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestRenderHumanLink(t *testing.T) {
	affected := func(ecosystems ...string) []*osvschema.Affected {
		out := make([]*osvschema.Affected, 0, len(ecosystems))
		for _, e := range ecosystems {
			out = append(out, &osvschema.Affected{Package: &osvschema.Package{Ecosystem: e, Name: "pkg"}})
		}

		return out
	}

	tests := []struct {
		name    string
		tmpl    string
		vuln    *osvschema.Vulnerability
		want    string
		wantErr bool
	}{
		{
			name: "empty",
			tmpl: "",
			vuln: &osvschema.Vulnerability{Id: "GHSA-xxxx-yyyy-zzzz"},
			want: "",
		},
		{
			name: "static",
			tmpl: "https://github.com/google/chromium-policy-vulnfeed/blob/main/advisories/",
			vuln: &osvschema.Vulnerability{Id: "V8-2024-1"},
			want: "https://github.com/google/chromium-policy-vulnfeed/blob/main/advisories/",
		},
		{
			name: "id",
			tmpl: "https://github.com/advisories/{{ .ID }}",
			vuln: &osvschema.Vulnerability{Id: "GHSA-xxxx-yyyy-zzzz"},
			want: "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
		},
		{
			name: "replace",
			tmpl: `https://security.alpinelinux.org/vuln/{{ .ID | replace "ALPINE-" "" }}`,
			vuln: &osvschema.Vulnerability{Id: "ALPINE-CVE-2024-1234"},
			want: "https://security.alpinelinux.org/vuln/CVE-2024-1234",
		},
		{
			name: "field",
			tmpl: `https://github.com/JuliaLang/SecurityAdvisories.jl/blob/main/advisories/published/{{ .ID | field "-" 1 }}/{{ .ID }}.md`,
			vuln: &osvschema.Vulnerability{Id: "JLSEC-2025-1"},
			want: "https://github.com/JuliaLang/SecurityAdvisories.jl/blob/main/advisories/published/2025/JLSEC-2025-1.md",
		},
		{
			name: "chained field, replace and lower",
			tmpl: `https://www.suse.com/support/update/announcement/{{ .ID | field ":" 0 | field "-" 2 }}/{{ .ID | replace ":" "" | lower }}/`,
			vuln: &osvschema.Vulnerability{Id: "SUSE-SU-2024:1234-1"},
			want: "https://www.suse.com/support/update/announcement/2024/suse-su-20241234-1/",
		},
		{
			name: "ecosystems",
			tmpl: `https://errata.almalinux.org/{{ index .Ecosystems 0 | field ":" 1 }}/{{ .ID | replace ":" "-" }}.html`,
			vuln: &osvschema.Vulnerability{Id: "ALSA-2024:1234", Affected: affected("AlmaLinux:8")},
			want: "https://errata.almalinux.org/8/ALSA-2024-1234.html",
		},
		{
			name:    "field out of range",
			tmpl:    `https://example.com/{{ .ID | field "-" 5 }}`,
			vuln:    &osvschema.Vulnerability{Id: "JLSEC-2025-1"},
			wantErr: true,
		},
		{
			name:    "no ecosystems",
			tmpl:    `https://errata.almalinux.org/{{ index .Ecosystems 0 | field ":" 1 }}/{{ .ID }}.html`,
			vuln:    &osvschema.Vulnerability{Id: "ALSA-2024:1234"},
			wantErr: true,
		},
		{
			// TODO(michaelkedar): Remove once the jinja fallback is removed.
			name: "legacy jinja fallback",
			tmpl: `https://ubuntu.com/security/{{ BUG_ID | replace("UBUNTU-", "") }}`,
			vuln: &osvschema.Vulnerability{Id: "UBUNTU-CVE-2024-1234"},
			want: "https://ubuntu.com/security/CVE-2024-1234",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RenderHumanLink(context.Background(), tt.tmpl, tt.vuln)
			if (err != nil) != tt.wantErr {
				t.Fatalf("RenderHumanLink() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("RenderHumanLink() = %q, want %q", got, tt.want)
			}
		})
	}
}
