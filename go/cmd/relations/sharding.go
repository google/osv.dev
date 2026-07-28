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

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"cloud.google.com/go/datastore"
	"golang.org/x/sync/errgroup"
	"google.golang.org/api/iterator"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// KeyShard represents a Datastore key range [Start, End) for sharded queries.
type KeyShard struct {
	Start string
	End   string
}

// expandBraceToken expands bash-style brace expressions (e.g. "CGA-{a..z}", "CGA-{0..9}")
// into individual prefix strings using mvdan.cc/sh/v3/expand.
func expandBraceToken(token string) []string {
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

// splitTokens splits a string by comma while respecting nested brace expressions like "{a,b,c}".
func splitTokens(str string) []string {
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

// ParseBreakdownPrefixes parses a comma-separated string of key prefix breakdowns into KeyShards.
// Tokens containing brace expressions like "CGA-{a,b,c}" are expanded using mvdan.cc/sh/v3/expand.
func ParseBreakdownPrefixes(str string) []KeyShard {
	if str == "" {
		return []KeyShard{{Start: "", End: ""}}
	}
	raw := splitTokens(str)
	var prefixes []string
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p != "" {
			expanded := expandBraceToken(p)
			prefixes = append(prefixes, expanded...)
		}
	}
	if len(prefixes) == 0 {
		return []KeyShard{{Start: "", End: ""}}
	}

	slices.Sort(prefixes)
	prefixes = slices.Compact(prefixes)

	shards := make([]KeyShard, 0, len(prefixes)+1)
	shards = append(shards, KeyShard{Start: "", End: prefixes[0]})
	for i := range len(prefixes) - 1 {
		shards = append(shards, KeyShard{Start: prefixes[i], End: prefixes[i+1]})
	}
	shards = append(shards, KeyShard{Start: prefixes[len(prefixes)-1], End: ""})

	return shards
}

// QueryFactory constructs a Datastore query scoped to a specific KeyShard.
// The factory function receives a KeyShard and returns a *datastore.Query with the
// appropriate key boundaries applied.
type QueryFactory func(shard KeyShard) *datastore.Query

// ItemHandler processes each retrieved Datastore entity E and its key sequentially.
type ItemHandler[E any] func(key *datastore.Key, entity *E)

type entityKeyPair[E any] struct {
	key    *datastore.Key
	entity E
}

// runShardedQuery executes a Datastore query concurrently across a set of key shards using an errgroup,
// streaming retrieved entities over a channel and passing them to the handle callback function sequentially.
//
// Type Parameters:
//   - E: The Datastore entity struct type being fetched (e.g. models.Vulnerability, models.RelatedGroup).
//
// Parameters:
//   - ctx: The context controlling lifecycle, timeout, and early cancellation across all worker goroutines.
//   - cl: The Datastore client used to run the queries.
//   - keyShards: A slice of KeyShard ranges defining the key boundaries to query in parallel.
//   - buildQuery: A QueryFactory callback that builds a *datastore.Query scoped to a given KeyShard.
//   - handle: An ItemHandler callback that receives each retrieved Datastore key and entity pointer sequentially.
//
// Returns the first error encountered during sharded query execution, if any.
func runShardedQuery[E any](
	ctx context.Context,
	cl *datastore.Client,
	keyShards []KeyShard,
	buildQuery QueryFactory,
	handle ItemHandler[E],
) error {
	g, ctx := errgroup.WithContext(ctx)
	resultsChan := make(chan entityKeyPair[E], 1000)

	for _, shard := range keyShards {
		g.Go(func() error {
			query := buildQuery(shard)
			it := cl.Run(ctx, query)
			for {
				var entity E
				key, err := it.Next(&entity)
				if errors.Is(err, iterator.Done) {
					break
				}
				if err != nil {
					return fmt.Errorf("failed to iterate shard [%s, %s): %w", shard.Start, shard.End, err)
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case resultsChan <- entityKeyPair[E]{key: key, entity: entity}:
				}
			}

			return nil
		})
	}

	go func() {
		_ = g.Wait()
		close(resultsChan)
	}()

	for pair := range resultsChan {
		handle(pair.key, &pair.entity)
	}

	return g.Wait()
}

// applyNameKeyFilter adds string NameKey boundaries [Start, End) to a Datastore query.
func applyNameKeyFilter(q *datastore.Query, kind string, shard KeyShard) *datastore.Query {
	if shard.Start != "" {
		q = q.FilterField("__key__", ">=", datastore.NameKey(kind, shard.Start, nil))
	}
	if shard.End != "" {
		q = q.FilterField("__key__", "<", datastore.NameKey(kind, shard.End, nil))
	}

	return q
}
