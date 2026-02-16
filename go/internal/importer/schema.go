package importer

import (
	_ "embed"
	"fmt"

	"github.com/xeipuuv/gojsonschema"
)

// Please run 'go generate ./...' to sync schema.json from the submodule.
//go:generate cp ../../../osv/osv-schema/validation/schema.json schema_generated.json

//go:embed schema_generated.json
var schemaBytes []byte

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
