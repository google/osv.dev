// Package schema provides utilities for validating OSV records against the JSON schema
// and checking for known ecosystems defined in the schema.
package schema

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/xeipuuv/gojsonschema"
)

// Run 'go generate ./...' to sync schema.json from the submodule.
//go:generate cp ../../../../osv/osv-schema/validation/schema.json schema_generated.json

//go:embed schema_generated.json
var schemaBytes []byte

var validEcosystems = populateValidEcosystems()

func populateValidEcosystems() map[osvconstants.Ecosystem]struct{} {
	var s struct {
		Defs struct {
			EcosystemName struct {
				Enum []string `json:"enum"`
			} `json:"ecosystemName"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(schemaBytes, &s); err != nil {
		panic("failed to parse embedded schema: " + err.Error())
	}
	m := make(map[osvconstants.Ecosystem]struct{})
	for _, e := range s.Defs.EcosystemName.Enum {
		m[osvconstants.Ecosystem(e)] = struct{}{}
	}

	return m
}

// IsKnownEcosystem returns true if the ecosystem is defined in the OSV schema.
// It handles ecosystem suffixes (e.g. "Debian:11" -> "Debian").
func IsKnownEcosystem(ecosystem string) bool {
	base, _, _ := strings.Cut(ecosystem, ":")
	_, ok := validEcosystems[osvconstants.Ecosystem(base)]

	return ok
}

// Validate checks the given data against the OSV JSON schema.
func Validate(data []byte) error {
	schemaLoader := gojsonschema.NewBytesLoader(schemaBytes)
	documentLoader := gojsonschema.NewBytesLoader(data)

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return fmt.Errorf("failed to run schema validation: %w", err)
	}

	if !result.Valid() {
		var errs string
		var errsSb63 strings.Builder
		for _, desc := range result.Errors() {
			fmt.Fprintf(&errsSb63, "- %s\n", desc)
		}
		errs += errsSb63.String()

		return fmt.Errorf("schema validation failed:\n%s", errs)
	}

	return nil
}

var jsonNullEscape = []byte(`\u0000`)

// ReplaceJSONNullEscapes rewrites unescaped JSON \u0000 escape sequences to \ufffd
// (U+FFFD replacement character), leaving escaped backslashes such as \\u0000 untouched.
//
// Although \u0000 is legal in JSON (RFC 8259) and protobuf strings, PostgreSQL rejects
// U+0000 in both TEXT and JSONB columns (SQLSTATE 22021 / 22P05). In valid JSON (including
// YAML converted via yaml.ToJSON), lowercase \u0000 is the only escape sequence that can
// decode to U+0000: JSON forbids uppercase \U escapes, '0' has no hex case, and UTF-16
// surrogate pairs only encode U+10000..U+10FFFF.
//
// When no unescaped \u0000 is present, data is returned as-is without allocation.
func ReplaceJSONNullEscapes(data []byte) []byte {
	copied := false
	for off := 0; ; {
		i := bytes.Index(data[off:], jsonNullEscape)
		if i < 0 {
			return data
		}
		pos := off + i

		// Count consecutive backslashes ending at data[pos] (the '\' of "\u0000").
		// An odd count means the final '\' starts a \u0000 escape (e.g. "\u0000" or "\\\u0000");
		// an even count means all backslashes are paired escapes before literal "u0000" (e.g. "\\u0000").
		bs := 1
		for pos-bs >= 0 && data[pos-bs] == '\\' {
			bs++
		}
		if bs%2 == 1 {
			if !copied {
				data = bytes.Clone(data)
				copied = true
			}
			// "\u0000" and "\ufffd" are both 6 bytes, so we can overwrite "0000" in place.
			copy(data[pos+2:pos+6], "fffd")
		}
		off = pos + 6
	}
}
