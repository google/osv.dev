package models

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/google/osv/vulnfeeds/utility/logger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

//nolint:recvcheck
type ConversionOutcome int

const (
	Extension = ".json"
)

const (
	// Set of enums for categorizing conversion outcomes.
	ConversionUnknown ConversionOutcome = iota // Shouldn't happen
	Successful                                 // It worked!
	Rejected                                   // The CVE was rejected
	NoSoftware                                 // The CVE had no CPEs relating to software (i.e. Operating Systems or Hardware).
	NoRepos                                    // The CPE Vendor/Product had no repositories derived for it.
	NoCommitRanges                             // No viable commit ranges could be calculated from the repository for the CVE's CPE(s).
	NoRanges                                   // No version ranges could be extracted from the record.
	FixUnresolvable                            // Partial resolution of versions, resulting in a false positive.
	Error                                      // An error occurred during conversion, e.g. a rate limit.
)

// RefTagDenyList contains reference tags that are often associated with unreliable or
// irrelevant repository URLs. References with these tags are currently ignored
// to avoid incorrect repository associations.
var RefTagDenyList = []string{
	// "Exploit",
	// "Third Party Advisory",
	"Broken Link", // Actively ignore these.
}

var conversionOutcomeStrings = [...]string{
	"ConversionUnknown", "Successful", "Rejected", "NoSoftware", "NoRepos", "NoCommitRanges", "NoRanges", "FixUnresolvable", "Error",
}

func (c ConversionOutcome) String() string {
	if int(c) >= 0 && int(c) < len(conversionOutcomeStrings) {
		return conversionOutcomeStrings[c]
	}

	return conversionOutcomeStrings[ConversionUnknown]
}

func (c ConversionOutcome) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

func (c *ConversionOutcome) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	for i, val := range conversionOutcomeStrings {
		if val == s {
			*c = ConversionOutcome(i)

			return nil
		}
	}

	return fmt.Errorf("invalid ConversionOutcome %q", s)
}

// ConversionMetrics holds the collected data about the conversion process for a single CVE.
type ConversionMetrics struct {
	CVEID                 CVEID                            `json:"id"`              // The CVE ID
	CNA                   string                           `json:"cna"`             // The CNA that assigned the CVE.
	Outcome               ConversionOutcome                `json:"outcome"`         // The final outcome of the conversion (e.g., "Successful", "Failed").
	Repos                 []string                         `json:"repos"`           // A list of repositories extracted from the CVE's references.
	RefTypesCount         map[osvschema.Reference_Type]int `json:"ref_types_count"` // A count of each type of reference found.
	VersionSources        []VersionSource                  `json:"version_sources"` // A list of the ways the versions were extracted
	Notes                 []string                         `json:"notes"`           // A collection of notes and warnings generated during conversion.
	CPEs                  []string                         `json:"cpes"`
	UnresolvedRangesCount int                              `json:"unresolved_ranges_count"`
	ResolvedRangesCount   int                              `json:"resolved_ranges_count"`
}

// AddNote adds a formatted note to the ConversionMetrics.
func (m *ConversionMetrics) AddNote(format string, a ...any) {
	m.Notes = append(m.Notes, fmt.Sprintf(format, a...))
	logger.Debug(fmt.Sprintf(format, a...), slog.String("cna", m.CNA), slog.String("cve", string(m.CVEID)))
}

// SetOutcome sets the outcome of the conversion only if it's not already set, or has become successful.
func (m *ConversionMetrics) SetOutcome(outcome ConversionOutcome) {
	if m.Outcome == ConversionUnknown { // TODO DOUBLE CHECK
		m.Outcome = outcome
	}
}

// AddSource appends a source to the ConversionMetrics
func (m *ConversionMetrics) AddSource(source VersionSource) {
	m.VersionSources = append(m.VersionSources, source)
}

// VersionSource indicates the source of the extracted version information.
type VersionSource string

const (
	VersionSourceNone        VersionSource = "NOVERS"
	VersionSourceAffected    VersionSource = "CVEAFFVERS"
	VersionSourceGit         VersionSource = "GITVERS"
	VersionSourceCPE         VersionSource = "CPEVERS"
	VersionSourceDescription VersionSource = "DESCRVERS"
	VersionSourceRefs        VersionSource = "REFS"
)

func DetermineOutcome(metrics *ConversionMetrics) {
	// check if we have affected ranges/versions.
	if len(metrics.Repos) == 0 {
		// Fix unlikely, as no repos to resolve
		metrics.SetOutcome(NoRepos)
		return
	}

	if metrics.ResolvedRangesCount > 0 {
		metrics.SetOutcome(Successful)
	} else if metrics.UnresolvedRangesCount > 0 {
		metrics.SetOutcome(NoCommitRanges)
	} else {
		metrics.SetOutcome(NoRanges)
	}
}
