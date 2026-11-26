// Package linter provides shared configuration and matching logic for provider-specific
// osv-linter finding suppressions across osv-linter-worker and the website query index.
package linter

import (
	_ "embed"
	"errors"
	"fmt"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"

	"go.yaml.in/yaml/v4"
)

//go:embed suppressions.yaml
var embeddedSuppressionsYAML []byte

// Rule defines a provider-specific linter suppression rule in YAML.
type Rule struct {
	Source       string  `yaml:"source"`
	Code         string  `yaml:"code"`
	Message      *string `yaml:"message"`
	MessageRegex string  `yaml:"message_regex"`
	BugIDRegex   string  `yaml:"bug_id_regex"`
	Reason       string  `yaml:"reason"`
}

type configFile struct {
	Suppressions []Rule `yaml:"suppressions"`
}

type compiledRule struct {
	code         string
	message      *string
	messageRegex *regexp.Regexp
	bugIDRegex   *regexp.Regexp
	reason       string
}

// Registry holds compiled provider-specific suppression rules indexed by source name.
type Registry struct {
	bySource map[string][]compiledRule
}

var defaultRegistryOnce = sync.OnceValues(func() (*Registry, error) {
	return ParseConfig(embeddedSuppressionsYAML)
})

// DefaultRegistry returns the compiled Registry built from the embedded suppressions.yaml.
func DefaultRegistry() *Registry {
	reg, err := defaultRegistryOnce()
	if err != nil {
		panic(fmt.Sprintf("invalid embedded linter suppressions.yaml: %v", err))
	}

	return reg
}

// LoadFile reads and compiles a linter suppressions YAML file from disk.
func LoadFile(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed reading suppressions file %q: %w", path, err)
	}

	return ParseConfig(data)
}

// ParseConfig parses and validates YAML suppression rules into a compiled Registry.
func ParseConfig(data []byte) (*Registry, error) {
	var cfg configFile
	if len(strings.TrimSpace(string(data))) > 0 {
		if err := yaml.Load(data, &cfg, yaml.WithKnownFields()); err != nil {
			if !strings.Contains(err.Error(), "no documents in stream") {
				return nil, fmt.Errorf("failed parsing suppressions YAML: %w", err)
			}
		}
	}

	bySource := make(map[string][]compiledRule)
	for i, r := range cfg.Suppressions {
		source := strings.TrimSpace(r.Source)
		if source == "" {
			return nil, fmt.Errorf("suppression rule %d: source is required", i)
		}
		reason := strings.TrimSpace(r.Reason)
		if reason == "" {
			return nil, fmt.Errorf("suppression rule %d (%s): reason is required", i, source)
		}

		code := strings.ToUpper(strings.TrimSpace(r.Code))
		if code == "*" {
			return nil, fmt.Errorf("suppression rule %d (%s): wildcard code \"*\" is not allowed; specify an explicit rule code or matcher", i, source)
		}

		if code == "" && r.Message == nil && r.MessageRegex == "" && r.BugIDRegex == "" {
			return nil, fmt.Errorf("suppression rule %d (%s): at least one of code, message, message_regex, or bug_id_regex must be set", i, source)
		}

		var msgRe *regexp.Regexp
		if r.MessageRegex != "" {
			var err error
			msgRe, err = regexp.Compile(r.MessageRegex)
			if err != nil {
				return nil, fmt.Errorf("suppression rule %d (%s): invalid message_regex %q: %w", i, source, r.MessageRegex, err)
			}
		}

		var bugRe *regexp.Regexp
		if r.BugIDRegex != "" {
			var err error
			bugRe, err = regexp.Compile(r.BugIDRegex)
			if err != nil {
				return nil, fmt.Errorf("suppression rule %d (%s): invalid bug_id_regex %q: %w", i, source, r.BugIDRegex, err)
			}
		}

		bySource[source] = append(bySource[source], compiledRule{
			code:         code,
			message:      r.Message,
			messageRegex: msgRe,
			bugIDRegex:   bugRe,
			reason:       reason,
		})
	}

	if len(bySource) == 0 && len(cfg.Suppressions) > 0 {
		return nil, errors.New("unexpected empty compiled suppression rules")
	}

	return &Registry{bySource: bySource}, nil
}

// Sources returns the sorted list of unique source names configured in this Registry.
func (r *Registry) Sources() []string {
	if r == nil {
		return nil
	}

	return slices.Sorted(maps.Keys(r.bySource))
}

// Match checks whether a linter finding on (source, bugID, code, message) is suppressed.
// If suppressed, it returns the configured human-readable reason and true.
func (r *Registry) Match(source, bugID, code, message string) (string, bool) {
	if r == nil {
		return "", false
	}
	rules := r.bySource[source]
	if len(rules) == 0 {
		return "", false
	}

	normCode := strings.ToUpper(strings.TrimSpace(code))
	for _, rule := range rules {
		if rule.code != "" && rule.code != normCode {
			continue
		}
		if rule.message != nil && *rule.message != message {
			continue
		}
		if rule.messageRegex != nil && !rule.messageRegex.MatchString(message) {
			continue
		}
		if rule.bugIDRegex != nil && !rule.bugIDRegex.MatchString(bugID) {
			continue
		}

		return rule.reason, true
	}

	return "", false
}
