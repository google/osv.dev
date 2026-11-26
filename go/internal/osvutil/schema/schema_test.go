// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package schema

import (
	"testing"

	"k8s.io/apimachinery/pkg/util/yaml"
)

func TestReplaceJSONNullEscapes(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "no null escapes",
			in:   `{"summary": "clean text"}`,
			want: `{"summary": "clean text"}`,
		},
		{
			name: "single unescaped null",
			in:   `{"summary": "nul\u0000byte"}`,
			want: `{"summary": "nul\ufffdbyte"}`,
		},
		{
			name: "consecutive nulls",
			in:   `{"summary": "\u0000\u0000"}`,
			want: `{"summary": "\ufffd\ufffd"}`,
		},
		{
			name: "even backslashes preserved (literal backslash + u0000)",
			in:   `{"details": "code: \\u0000 and \\\\u0000"}`,
			want: `{"details": "code: \\u0000 and \\\\u0000"}`,
		},
		{
			name: "odd backslashes rewritten (literal backslash + null escape)",
			in:   `{"details": "\\\u0000 and \\\\\u0000"}`,
			want: `{"details": "\\\ufffd and \\\\\ufffd"}`,
		},
		{
			name: "null escape in object key",
			in:   `{"bad\u0000key": "val"}`,
			want: `{"bad\ufffdkey": "val"}`,
		},
		{
			name: "null escape at index 0",
			in:   `\u0000`,
			want: `\ufffd`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := []byte(tt.in)
			snap := string(orig)
			got := ReplaceJSONNullEscapes(orig)
			if string(got) != tt.want {
				t.Errorf("ReplaceJSONNullEscapes(%s) = %s, want %s", tt.in, got, tt.want)
			}
			if string(orig) != snap {
				t.Errorf("ReplaceJSONNullEscapes mutated caller slice: got %s, want %s", orig, snap)
			}
			if tt.in == tt.want && len(orig) > 0 && &got[0] != &orig[0] {
				t.Errorf("ReplaceJSONNullEscapes allocated a new slice when no replacement was needed")
			}
		})
	}

	t.Run("YAML \\0 escape converted via yaml.ToJSON", func(t *testing.T) {
		yamlData := []byte("summary: \"yaml\\0null and \\\\u0000\"\n")
		jsonData, err := yaml.ToJSON(yamlData)
		if err != nil {
			t.Fatalf("yaml.ToJSON failed: %v", err)
		}
		got := string(ReplaceJSONNullEscapes(jsonData))
		want := `{"summary":"yaml\ufffdnull and \\u0000"}`
		if got != want {
			t.Errorf("got %s, want %s", got, want)
		}
	})
}

func TestSanitizeJSON(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{
			name: "valid UTF-8 returns input without allocation",
			in:   []byte(`{"summary": "clean text — utf8"}`),
			want: `{"summary": "clean text — utf8"}`,
		},
		{
			name: "invalid UTF-8 replaced",
			in:   []byte("{\"summary\": \"bad\xffbyte\"}"),
			want: "{\"summary\": \"bad\uFFFDbyte\"}",
		},
		{
			name: "raw NUL byte replaced",
			in:   []byte("{\"summary\": \"raw\x00nul\"}"),
			want: "{\"summary\": \"raw\uFFFDnul\"}",
		},
		{
			name: "unescaped JSON null escape replaced and escaped preserved",
			in:   []byte(`{"summary": "\u0000 and \\u0000"}`),
			want: `{"summary": "\ufffd and \\u0000"}`,
		},
		{
			name: "combined invalid UTF-8, raw NUL, and JSON null escape",
			in:   []byte("{\"summary\": \"\xff\x00\\u0000\\\\u0000\"}"),
			want: "{\"summary\": \"\uFFFD\uFFFD\\ufffd\\\\u0000\"}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := append([]byte(nil), tt.in...)
			snap := string(orig)
			got := SanitizeJSON(orig)
			if string(got) != tt.want {
				t.Errorf("SanitizeJSON(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if string(orig) != snap {
				t.Errorf("SanitizeJSON mutated caller slice: got %q, want %q", orig, snap)
			}
			if string(tt.in) == tt.want && len(orig) > 0 && &got[0] != &orig[0] {
				t.Errorf("SanitizeJSON allocated a new slice when input was already clean")
			}
		})
	}
}
