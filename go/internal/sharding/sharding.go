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

// ExpandBreakdownPrefixes parses a comma-separated string of prefix breakdowns, expanding brace expressions
// (e.g. "CGA-{{0..9},{a..z}}") into individual sorted, deduplicated prefix strings.
func ExpandBreakdownPrefixes(str string) []string {
	if str == "" {
		return nil
	}

	w := &syntax.Word{Parts: []syntax.WordPart{&syntax.Lit{Value: str}}}
	syntax.SplitBraces(w)

	var prefixes []string
	printer := syntax.NewPrinter()
	for _, word := range expand.Braces(w) {
		var buf bytes.Buffer
		_ = printer.Print(&buf, word)
		for _, p := range strings.Split(buf.String(), ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				prefixes = append(prefixes, p)
			}
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

// QueryFactory constructs a Datastore query scoped to a specific KeyShard.
type QueryFactory func(shard KeyShard) *datastore.Query

// ItemHandler processes each retrieved Datastore entity E and its key sequentially.
type ItemHandler[E any] func(key *datastore.Key, entity *E)

type entityKeyPair[E any] struct {
	key    *datastore.Key
	entity E
}

// RunShardedQuery executes a Datastore query concurrently across a set of key shards using an errgroup,
// streaming retrieved entities over a channel and passing them to the handle callback function sequentially.
func RunShardedQuery[E any](
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

// ApplyNameKeyFilter applies a key range filter [shard.Start, shard.End) to a Datastore query using __key__.
func ApplyNameKeyFilter(query *datastore.Query, kind string, shard KeyShard) *datastore.Query {
	if shard.Start != "" {
		query = query.FilterField("__key__", ">=", datastore.NameKey(kind, shard.Start, nil))
	}
	if shard.End != "" {
		query = query.FilterField("__key__", "<", datastore.NameKey(kind, shard.End, nil))
	}

	return query
}
