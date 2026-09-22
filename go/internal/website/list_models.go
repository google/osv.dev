package website

import (
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// EcosystemCount represents an ecosystem filter option and its vulnerability count.
type EcosystemCount = models.EcosystemCount

// ListedVulnerabilityDisplay wraps models.ListedVulnerability with website presentation methods.
type ListedVulnerabilityDisplay models.ListedVulnerability

// FormattedPublished returns the published timestamp in RFC3339 format.
func (v ListedVulnerabilityDisplay) FormattedPublished() string {
	if v.Published.IsZero() {
		return ""
	}

	return v.Published.Format(time.RFC3339)
}

// RelativePublished returns a human-readable relative time representation.
func (v ListedVulnerabilityDisplay) RelativePublished() string {
	if v.Published.IsZero() {
		return ""
	}

	return formatRelativeTime(v.Published, time.Now())
}

func formatRelativeTime(value, now time.Time) string {
	if value.IsZero() {
		return ""
	}

	diff := max(now.Sub(value), 0)

	diffSeconds := int64(diff.Seconds())
	diffMinutes := diffSeconds / 60
	diffHours := diffSeconds / 3600
	diffDays := diffSeconds / 86400

	if diffMinutes == 0 {
		return "just now"
	}
	if diffHours == 0 {
		if diffMinutes == 1 {
			return "1 minute ago"
		}

		return fmt.Sprintf("%d minutes ago", diffMinutes)
	}
	if diffDays == 0 {
		if diffHours == 1 {
			return "1 hour ago"
		}

		return fmt.Sprintf("%d hours ago", diffHours)
	}
	if diffDays == 1 {
		return "yesterday"
	}
	if diffDays < 7 {
		return fmt.Sprintf("%d days ago", diffDays)
	}
	if value.Year() == now.Year() {
		return value.Format("02 Jan")
	}

	return value.Format("02 Jan 2006")
}

func stripScheme(rawURL string) string {
	if _, after, ok := strings.Cut(rawURL, "://"); ok {
		return after
	}

	return rawURL
}

// DisplayPackages returns up to 5 formatted package strings to display in the table row.
func (v ListedVulnerabilityDisplay) DisplayPackages() []string {
	if len(v.Packages) == 0 {
		return nil
	}

	limit := min(len(v.Packages), 5)

	result := make([]string, 0, limit)
	for i := range limit {
		pkg := v.Packages[i]
		if pkg.Repo != "" {
			result = append(result, stripScheme(pkg.Repo))
		} else if pkg.Package != nil {
			if pkg.Package.GetEcosystem() == "" {
				result = append(result, pkg.Package.GetName())
			} else {
				result = append(result, pkg.Package.GetEcosystem()+"/"+pkg.Package.GetName())
			}
		}
	}

	return result
}

// RemainingPackageCount returns the number of additional packages beyond the first 5.
func (v ListedVulnerabilityDisplay) RemainingPackageCount() int {
	return max(0, len(v.Packages)-5)
}

// truncate ensures that the given string is shorter than 80 characters.
//
// If the string is longer than that limit, it's trimmed and suffixed with an ellipsis.
// Ideally the string will be trimmed at the space that's closest to the limit to
// preserve whole words; if a string has no spaces before the limit, it'll be forcefully truncated.
func truncate(str string) string {
	count := 0
	truncateAt := -1

	for i, c := range str {
		if unicode.IsSpace(c) {
			truncateAt = i
		}

		count++

		if count >= 80 {
			// ideally we want to keep words whole when truncating,
			// but if we can't find a space just truncate at the limit
			if truncateAt == -1 {
				_, size := utf8.DecodeRuneInString(str[i:])
				truncateAt = i + size
			}

			return str[:truncateAt] + "..."
		}
	}

	return str
}

func (v ListedVulnerabilityDisplay) Describe() string {
	builder := strings.Builder{}
	if v.Details == "" {
		builder.WriteString("See record for full details")
	} else {
		builder.WriteString(truncate(v.Details))
	}

	return builder.String()
}

func cvssRank(t osvschema.Severity_Type) int {
	switch t {
	case osvschema.Severity_CVSS_V4:
		return 3
	case osvschema.Severity_CVSS_V3:
		return 2
	case osvschema.Severity_CVSS_V2:
		return 1
	default:
		return 0
	}
}

// PrimarySeverity returns the computed SeverityDisplay for the primary severity entry.
func (v ListedVulnerabilityDisplay) PrimarySeverity() *SeverityDisplay {
	var bestDisplay *SeverityDisplay
	bestRank := 0

	for _, sev := range v.Severities {
		if display, ok := ParseSeverityDisplay(sev.GetType(), sev.GetScore(), v.ID); ok {
			rank := cvssRank(sev.GetType())
			if rank > bestRank {
				bestRank = rank
				bestDisplay = &display
			}
		}
	}

	return bestDisplay
}

// ListPageData holds the page context passed to list.html template.
type ListPageData struct {
	BasePageData

	Query               string
	SelectedEcosystem   string
	CurrentAfter        string
	NextAfter           string
	EcosystemCounts     []EcosystemCount
	TotalEcosystemCount int
	Vulnerabilities     []ListedVulnerabilityDisplay
}
