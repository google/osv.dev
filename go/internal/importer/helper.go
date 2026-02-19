package importer

import (
	"log/slog"
	"regexp"
	"slices"
	"strings"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/logger"
)

func negatedPrefix(regex string) (string, bool) {
	// We have a bunch of ignore patterns in the form "^(?!DB_ID-).*$"
	// This is silly, since we're already enforcing prefix matches
	// This is a check to see if we can skip those ignore patterns
	// (since go doesn't support negative lookaheads)
	// TODO(michaelkedar): Remove this function + regexes from source repos
	const prefix = "^(?!"
	const suffix = ").*$"
	if strings.HasPrefix(regex, prefix) && strings.HasSuffix(regex, suffix) {
		return strings.TrimSuffix(strings.TrimPrefix(regex, prefix), suffix), true
	}

	return "", false
}

func compileIgnorePatterns(sourceRepo *models.SourceRepository) []*regexp.Regexp {
	compiledIgnorePatterns := make([]*regexp.Regexp, 0, len(sourceRepo.IgnorePatterns))
	for _, pattern := range sourceRepo.IgnorePatterns {
		// There's a bunch on negative lookaheads in the ignore patterns that check if the file begins with an ID prefix
		// We can remove those patterns since we're already checking for prefix matches
		if prefix, ok := negatedPrefix(pattern); ok {
			if slices.Contains(sourceRepo.IDPrefixes, prefix) {
				continue
			}
		}
		compiledPattern, err := regexp.Compile(pattern)
		if err != nil {
			logger.Warn("Failed to compile ignore pattern",
				slog.String("source", sourceRepo.Name),
				slog.String("pattern", pattern),
				slog.Any("error", err))

			continue
		}

		compiledIgnorePatterns = append(compiledIgnorePatterns, compiledPattern)
	}

	return compiledIgnorePatterns
}

// shouldIgnore checks if the given name matches any of the ID prefixes and ignore patterns.
func shouldIgnore(name string, idPrefixes []string, ignorePatterns []*regexp.Regexp) bool {
	if len(idPrefixes) > 0 {
		prefixMatch := false
		for _, prefix := range idPrefixes {
			if strings.HasPrefix(name, prefix) {
				prefixMatch = true
				break
			}
		}
		if !prefixMatch {
			return true
		}
	}

	for _, compiledIgnorePattern := range ignorePatterns {
		if compiledIgnorePattern.MatchString(name) {
			return true
		}
	}

	return false
}

func extensionToFormat(extension string) RecordFormat {
	switch strings.ToLower(extension) {
	case ".json":
		return RecordFormatJSON
	case ".yaml", ".yml":
		return RecordFormatYAML
	default:
		return RecordFormatUnknown
	}
}
