// Package schema provides utilities for validating OSV records against the JSON schema
// and checking for known ecosystems defined in the schema.
package schema

import (
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
		for _, desc := range result.Errors() {
			errs += fmt.Sprintf("- %s\n", desc)
		}

		return fmt.Errorf("schema validation failed:\n%s", errs)
	}

	return nil
}
