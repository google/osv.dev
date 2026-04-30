// Package registry contains all the enrichers that are used in the worker pipeline.
package registry

import (
	"github.com/google/osv.dev/go/internal/worker/pipeline"
	"github.com/google/osv.dev/go/internal/worker/pipeline/sourcelink"
)

// List is the list of all enrichers used in the worker pipeline.
var List = []pipeline.Enricher{
	&sourcelink.Enricher{},
}
