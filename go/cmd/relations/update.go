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
	"log/slog"
	"slices"
	"sync"
	"time"

	"cloud.google.com/go/datastore"
	"cloud.google.com/go/pubsub/v2"
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
	Value     any
}

type Updater struct {
	Ch        chan Update
	wg        sync.WaitGroup
	dsClient  *datastore.Client
	gcsClient clients.CloudStorage
	publisher clients.Publisher
}

func NewUpdater(ctx context.Context, dsClient *datastore.Client, gcsClient clients.CloudStorage, publisher clients.Publisher) *Updater {
	u := &Updater{
		Ch:        make(chan Update),
		dsClient:  dsClient,
		gcsClient: gcsClient,
		publisher: publisher,
	}
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		u.run(ctx)
	}()

	return u
}

func (u *Updater) run(ctx context.Context) {
	allUpdates := make(map[string][]Update)
	for {
		select {
		case <-ctx.Done():
			logger.Info("updater context cancelled")
			return
		case update, ok := <-u.Ch:
			if ok {
				allUpdates[update.ID] = append(allUpdates[update.ID], update)
				continue
			}
			// Channel was closed, collate updates and write
			// TODO: Parallelize these updates using a worker pool.
			for id, updates := range allUpdates {
				// Get the vulnerability from GCS
				path := id + ".pb"
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

				hasUpdates := false
				var modified time.Time
				for _, u := range updates {
					switch u.Field {
					case updateFieldAlias:
						val, ok := u.Value.([]string)
						if !ok {
							logger.Error("updated aliases are not []string", slog.String("id", id))
							continue
						}
						if slices.Compare(v.Aliases, val) == 0 {
							// No actual changes, do not update
							continue
						}
						hasUpdates = true
						v.Aliases = val
						if u.Timestamp.After(modified) {
							modified = u.Timestamp
						}
					default:
						logger.Error("unsupported update field", slog.Any("updateField", u.Field), slog.String("id", id))

					}
				}
				if !hasUpdates {
					continue
				}
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
					tx.Rollback()
					continue
				}
				vuln.Modified = modified
				if _, err := tx.Put(key, &vuln); err != nil {
					logger.Error("failed to put vuln to Datastore", slog.String("id", id), slog.Any("err", err))
					tx.Rollback()
					continue
				}
				listedVuln := models.NewListedVulnerabilityFromProto(v)
				listedKey := datastore.NameKey("ListedVulnerability", id, nil)
				if _, err := tx.Put(listedKey, listedVuln); err != nil {
					logger.Error("failed to put listed vuln to Datastore", slog.String("id", id), slog.Any("err", err))
					tx.Rollback()
					continue
				}
				if _, err := tx.Commit(); err != nil {
					logger.Error("failed to commit transaction", slog.String("id", id), slog.Any("err", err))
					continue
				}

				// Update GCS
				newData, err := proto.Marshal(v)
				if err != nil {
					logger.Error("failed to marshal vuln", slog.String("id", id), slog.Any("err", err))
					continue
				}
				opts := &clients.WriteOptions{
					IfGenerationMatches: &attrs.Generation,
				}
				if err := u.gcsClient.WriteObject(ctx, path, newData, opts); err != nil {
					logger.Error("failed to write vuln to GCS", slog.String("id", id), slog.Any("err", err))
					msg := &pubsub.Message{
						Attributes: map[string]string{},
					}
					if errors.Is(err, clients.ErrPreconditionFailed) {
						msg.Attributes["type"] = "gcs_gen_mismatch"
						msg.Attributes["id"] = id
						msg.Attributes["field"] = "aliases" // TODO: Make this dynamic if we support other fields
					} else {
						msg.Data = newData
						msg.Attributes["type"] = "gcs_retry"
					}
					u.publisher.Publish(ctx, msg)
					continue
				}
				logger.Info("updated vuln", slog.String("id", id))
			}
			return
		}
	}
}

func (u *Updater) Finish() {
	close(u.Ch)
	u.wg.Wait()
}
