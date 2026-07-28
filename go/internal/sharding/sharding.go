// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package sharding provides shared key and prefix sharding utilities across Go commands.
package sharding

import (
	"bytes"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// KeyShard represents a Datastore key range [Start, End) for sharded queries.
type KeyShard struct {
	Start string
	End   string
}

// ExpandBraceToken expands bash-style brace expressions (e.g. "CGA-{a..z}", "CGA-{0..9}")
// into individual prefix strings using mvdan.cc/sh/v3/expand.
func ExpandBraceToken(token string) []string {
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	word, err := parser.Document(strings.NewReader(token))
	if err != nil {
		return []string{token}
	}

	syntax.SplitBraces(word)
	words := expand.Braces(word)
	results := make([]string, 0, len(words))
	printer := syntax.NewPrinter()
	for _, w := range words {
		var buf bytes.Buffer
		_ = printer.Print(&buf, w)
		results = append(results, buf.String())
	}

	return results
}

// SplitTokens splits a string by comma while respecting nested brace expressions like "{a,b,c}".
func SplitTokens(str string) []string {
	var tokens []string
	var current strings.Builder
	depth := 0
	for _, r := range str {
		switch r {
		case '{':
			depth++
			current.WriteRune(r)
		case '}':
			if depth > 0 {
				depth--
			}
			current.WriteRune(r)
		case ',':
			if depth == 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			} else {
				current.WriteRune(r)
			}
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	return tokens
}

// ExpandBreakdownPrefixes parses a comma-separated string of prefix breakdowns, expanding brace expressions
// (e.g. "CGA-{a..c}") into individual sorted, deduplicated prefix strings.
func ExpandBreakdownPrefixes(str string) []string {
	if str == "" {
		return nil
	}
	raw := SplitTokens(str)
	var prefixes []string
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p != "" {
			expanded := ExpandBraceToken(p)
			prefixes = append(prefixes, expanded...)
		}
	}
	if len(prefixes) == 0 {
		return nil
	}

	slices.Sort(prefixes)

	return slices.Compact(prefixes)
}

// ParseBreakdownPrefixes parses a comma-separated string of key prefix breakdowns into KeyShards.
// Tokens containing brace expressions like "CGA-{a..z}" are expanded using ExpandBreakdownPrefixes.
func ParseBreakdownPrefixes(str string) []KeyShard {
	prefixes := ExpandBreakdownPrefixes(str)
	if len(prefixes) == 0 {
		return []KeyShard{{Start: "", End: ""}}
	}

	shards := make([]KeyShard, 0, len(prefixes)+1)
	shards = append(shards, KeyShard{Start: "", End: prefixes[0]})
	for i := range len(prefixes) - 1 {
		shards = append(shards, KeyShard{Start: prefixes[i], End: prefixes[i+1]})
	}
	shards = append(shards, KeyShard{Start: prefixes[len(prefixes)-1], End: ""})

	return shards
}
