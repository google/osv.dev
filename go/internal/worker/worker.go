// Package worker contains the implementation for the vulnerability enrichment worker pipeline.
package worker

import (
	"time"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/osv/clients"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

type TaskType int

const (
	TaskUnknown TaskType = iota
	TaskUpdate
	TaskDelete
)

type Task struct {
	Type         TaskType
	Vuln         *osvschema.Vulnerability
	SourceID     string
	PathInSource string
	// ReceivedTime is when the importer requested the vuln to be processed.
	ReceivedTime *time.Time
	// SourceTime is the modified time according to the source
	SourceTime *time.Time
	// SHA256 is only used when Vuln is not provided
	SHA256 string
}

type Stores struct {
	SourceRepo    models.SourceRepositoryStore
	Vulnerability models.VulnerabilityStore
	PyPIPublisher clients.Publisher
}
