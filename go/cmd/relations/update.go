// Copyright 2025 Google LLC
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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/datastore"
	"cloud.google.com/go/pubsub/v2"
	osvdatastore "github.com/google/osv.dev/go/internal/database/datastore"
	domainmodels "github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/clients"
	"github.com/google/osv.dev/go/osv/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type updateField int

const (
	updateFieldAlias updateField = iota
	updateFieldUpstream
	updateFieldRelated
)

type Update struct {
	ID        string
	Timestamp time.Time
	Field     updateField
	Value     []string
}

type Updater struct {
	Ch          chan Update
	wg          sync.WaitGroup
	dsClient    *datastore.Client
	gcsClient   clients.CloudStorage
	publisher   clients.Publisher
	pgVulnStore domainmodels.VulnerabilityStore
}

func NewUpdater(ctx context.Context, dsClient *datastore.Client, gcsClient clients.CloudStorage, publisher clients.Publisher) *Updater {
	return NewUpdaterWithPostgres(ctx, dsClient, gcsClient, publisher, nil)
}

func NewUpdaterWithPostgres(ctx context.Context, dsClient *datastore.Client, gcsClient clients.CloudStorage, publisher clients.Publisher, pgVulnStore domainmodels.VulnerabilityStore) *Updater {
	u := &Updater{
		Ch:          make(chan Update),
		dsClient:    dsClient,
		gcsClient:   gcsClient,
		publisher:   publisher,
		pgVulnStore: pgVulnStore,
	}
	u.wg.Go(func() {
		u.run(ctx)
	})

	return u
}

func (u *Updater) run(ctx context.Context) {
	allUpdates := make(map[string][]Update)
ConsumerLoop:
	for {
		select {
		case <-ctx.Done():
			logger.Info("updater context cancelled")
			return
		case update, ok := <-u.Ch:
			if !ok {
				break ConsumerLoop // Channel closed
			}
			allUpdates[update.ID] = append(allUpdates[update.ID], update)
		}
	}

	// Channel was closed, collate updates and write
	// TODO: Parallelize these updates using a worker pool.
	for id, updates := range allUpdates {
		// Get the vulnerability from GCS
		path := fmt.Sprintf("all/pb/%s.pb", id)
		data, err := u.gcsClient.ReadObject(ctx, path)
		if err != nil {
			if errors.Is(err, clients.ErrNotFound) {
				// Check if it exists in Datastore. If it does, it's an error that it's missing from GCS.
				// If it doesn't exist in Datastore either, it's likely just an alias ID that isn't a full OSV record,
				// which is expected and we can safely skip it.
				var vuln models.Vulnerability
				key := datastore.NameKey("Vulnerability", id, nil)
				if err := u.dsClient.Get(ctx, key, &vuln); err == nil {
					logger.Error("vulnerability exists in Datastore but missing from GCS", slog.String("id", id))
					msg := &pubsub.Message{
						Attributes: map[string]string{
							"type": "gcs_missing",
							"id":   id,
						},
					}
					u.publisher.Publish(ctx, msg)
				}

				continue
			}
			logger.Error("failed to read vuln from GCS", slog.String("id", id), slog.Any("err", err))

			continue
		}
		attrs, err := u.gcsClient.ReadObjectAttrs(ctx, path)
		if err != nil {
			logger.Error("failed to read vuln attrs from GCS", slog.String("id", id), slog.Any("err", err))
			continue
		}

		v := &osvschema.Vulnerability{}
		if err := proto.Unmarshal(data, v); err != nil {
			logger.Error("failed to unmarshal vuln", slog.String("id", id), slog.Any("err", err))
			continue
		}

		updatedFields, modified := applyUpdates(v, id, updates)
		if len(updatedFields) == 0 {
			continue
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		modified = nextModified(v.GetModified(), modified, now)
		v.Modified = timestamppb.New(modified)

		// Update Datastore
		tx, err := u.dsClient.NewTransaction(ctx)
		if err != nil {
			logger.Error("failed to start transaction", slog.String("id", id), slog.Any("err", err))
			continue
		}
		var vuln models.Vulnerability
		key := datastore.NameKey("Vulnerability", id, nil)
		if err := tx.Get(key, &vuln); err != nil {
			logger.Error("failed to get vuln from Datastore", slog.String("id", id), slog.Any("err", err))
			if err := tx.Rollback(); err != nil {
				logger.Error("failed to rollback transaction", slog.String("id", id), slog.Any("err", err))
			}

			continue
		}
		vuln.Modified = modified
		if _, err := tx.Put(key, &vuln); err != nil {
			logger.Error("failed to put vuln to Datastore", slog.String("id", id), slog.Any("err", err))
			if err := tx.Rollback(); err != nil {
				logger.Error("failed to rollback transaction", slog.String("id", id), slog.Any("err", err))
			}

			continue
		}
		listedKey := datastore.NameKey("ListedVulnerability", id, nil)
		if vuln.IsWithdrawn || v.GetWithdrawn() != nil {
			if err := tx.Delete(listedKey); err != nil && !errors.Is(err, datastore.ErrNoSuchEntity) {
				logger.Error("failed to delete listed vuln from Datastore", slog.String("id", id), slog.Any("err", err))
				if err := tx.Rollback(); err != nil {
					logger.Error("failed to rollback transaction", slog.String("id", id), slog.Any("err", err))
				}

				continue
			}
		} else {
			listedVuln := osvdatastore.NewListedVulnerabilityFromProto(v)
			if _, err := tx.Put(listedKey, listedVuln); err != nil {
				logger.Error("failed to put listed vuln to Datastore", slog.String("id", id), slog.Any("err", err))
				if err := tx.Rollback(); err != nil {
					logger.Error("failed to rollback transaction", slog.String("id", id), slog.Any("err", err))
				}

				continue
			}
		}
		if _, err := tx.Commit(); err != nil {
			logger.Error("failed to commit transaction", slog.String("id", id), slog.Any("err", err))
			continue
		}

		// Update PostgreSQL regardless of whether the GCS write below hits a generation
		// mismatch (which delegates GCS repair to recoverer), since PostgreSQL Mutate
		// runs its own optimistic-concurrency retry loop.
		if u.pgVulnStore != nil {
			_, err := u.pgVulnStore.Mutate(ctx, id, func(pgVuln *osvschema.Vulnerability) (bool, error) {
				if fields, _ := applyUpdates(pgVuln, id, updates); len(fields) == 0 {
					return false, nil
				}
				pgVuln.Modified = timestamppb.New(nextModified(pgVuln.GetModified(), modified, now))

				return true, nil
			})
			if err != nil && !errors.Is(err, domainmodels.ErrNotFound) {
				logger.Error("failed to update vuln in postgres", slog.String("id", id), slog.Any("err", err))
			}
		}

		// Update GCS
		newData, err := proto.Marshal(v)
		if err != nil {
			logger.Error("failed to marshal vuln", slog.String("id", id), slog.Any("err", err))
			continue
		}
		opts := &clients.WriteOptions{
			IfGenerationMatches: &attrs.Generation,
			CustomTime:          &modified,
		}
		if err := u.gcsClient.WriteObject(ctx, path, newData, opts); err != nil {
			logger.Error("failed to write vuln to GCS", slog.String("id", id), slog.Any("err", err))
			msg := &pubsub.Message{
				Attributes: map[string]string{},
			}
			if errors.Is(err, clients.ErrPreconditionFailed) {
				msg.Attributes["type"] = "gcs_gen_mismatch"
				msg.Attributes["id"] = id
				msg.Attributes["field"] = strings.Join(updatedFields, ",")
			} else {
				msg.Data = newData
				msg.Attributes["type"] = "gcs_retry"
			}
			u.publisher.Publish(ctx, msg)

			continue
		}
		logger.Info("updated vuln", slog.String("id", id))
	}
}

func (u *Updater) Finish() {
	close(u.Ch)
	u.wg.Wait()
}

// nextModified returns a monotonic modified timestamp: candidate if it is newer
// than current, otherwise now (or current if ahead of now).
func nextModified(current *timestamppb.Timestamp, candidate, now time.Time) time.Time {
	if current == nil || candidate.After(current.AsTime()) {
		return candidate
	}
	if now.After(current.AsTime()) {
		return now
	}

	return current.AsTime()
}

func applyUpdates(v *osvschema.Vulnerability, id string, updates []Update) ([]string, time.Time) {
	var updatedFields []string
	var modified time.Time
	for _, upd := range updates {
		var dst *[]string
		var name string
		switch upd.Field {
		case updateFieldAlias:
			dst, name = &v.Aliases, "aliases"
		case updateFieldUpstream:
			dst, name = &v.Upstream, "upstream"
		case updateFieldRelated:
			dst, name = &v.Related, "related"
		default:
			logger.Error("unsupported update field", slog.Any("updateField", upd.Field), slog.String("id", id))
			continue
		}
		if slices.Equal(*dst, upd.Value) {
			continue
		}
		*dst = upd.Value
		updatedFields = append(updatedFields, name)
		if upd.Timestamp.After(modified) {
			modified = upd.Timestamp
		}
	}

	return updatedFields, modified
}
