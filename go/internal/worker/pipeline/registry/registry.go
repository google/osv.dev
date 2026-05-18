// Package registry contains all the enrichers that are used in the worker pipeline.
package registry

import (
	"github.com/google/osv.dev/go/internal/worker/pipeline"
	"github.com/google/osv.dev/go/internal/worker/pipeline/enumerateversions"
	"github.com/google/osv.dev/go/internal/worker/pipeline/filterecosystem"
	"github.com/google/osv.dev/go/internal/worker/pipeline/makesemver"
	"github.com/google/osv.dev/go/internal/worker/pipeline/namenormalize"
	"github.com/google/osv.dev/go/internal/worker/pipeline/published"
	"github.com/google/osv.dev/go/internal/worker/pipeline/purl"
	"github.com/google/osv.dev/go/internal/worker/pipeline/relations"
	"github.com/google/osv.dev/go/internal/worker/pipeline/schemaversion"
	"github.com/google/osv.dev/go/internal/worker/pipeline/sourcelink"
)

// List is the list of all enrichers used in the worker pipeline.
var List = []pipeline.Enricher{
	&namenormalize.Enricher{},
	&filterecosystem.Enricher{},
	&makesemver.Enricher{},
	&enumerateversions.Enricher{},
	&schemaversion.Enricher{},
	&purl.Enricher{},
	&sourcelink.Enricher{},
	&published.Enricher{},
	&relations.Enricher{},
}
