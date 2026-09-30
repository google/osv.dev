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

package datastore

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"cloud.google.com/go/datastore"
	"github.com/google/osv.dev/go/internal/models"
)

const (
	UbuntuPackageMappingKind = "UbuntuPackageMapping"

	maxDatastoreGetMultiBatchSize = 1000
	maxDatastorePutMultiBatchSize = 500
)

type ubuntuPackageMappingEntity struct {
	SourceNames []string `datastore:"source_names,noindex"`
}

// UbuntuPackageMappingStore implements models.UbuntuPackageMappingStore using Cloud Datastore.
type UbuntuPackageMappingStore struct {
	client *datastore.Client
}

var _ models.UbuntuPackageMappingStore = (*UbuntuPackageMappingStore)(nil)

// NewUbuntuPackageMappingStore creates a new UbuntuPackageMappingStore.
func NewUbuntuPackageMappingStore(client *datastore.Client) *UbuntuPackageMappingStore {
	return &UbuntuPackageMappingStore{client: client}
}

// GetMulti retrieves mappings for a slice of binary package names.
// Any binary not found in Datastore will return an UbuntuPackageMapping with an empty SourceNames slice.
func (s *UbuntuPackageMappingStore) GetMulti(ctx context.Context, binaryNames []string) ([]*models.UbuntuPackageMapping, error) {
	results := make([]*models.UbuntuPackageMapping, 0, len(binaryNames))

	for chunkNames := range slices.Chunk(binaryNames, maxDatastoreGetMultiBatchSize) {
		keys := make([]*datastore.Key, len(chunkNames))
		entities := make([]*ubuntuPackageMappingEntity, len(chunkNames))
		for j, name := range chunkNames {
			keys[j] = datastore.NameKey(UbuntuPackageMappingKind, name, nil)
		}

		if err := s.client.GetMulti(ctx, keys, entities); err != nil {
			multiErr, ok := errors.AsType[datastore.MultiError](err)
			if !ok {
				return nil, fmt.Errorf("failed to get multi UbuntuPackageMapping: %w", err)
			}
			for j, e := range multiErr {
				if errors.Is(e, datastore.ErrNoSuchEntity) {
					entities[j] = nil
				} else if e != nil {
					return nil, fmt.Errorf("failed to get multi UbuntuPackageMapping: %w", err)
				}
			}
		}

		for j, name := range chunkNames {
			sourceNames := []string{}
			if entities[j] != nil && len(entities[j].SourceNames) > 0 {
				sourceNames = entities[j].SourceNames
			}
			results = append(results, &models.UbuntuPackageMapping{
				BinaryName:  name,
				SourceNames: sourceNames,
			})
		}
	}

	return results, nil
}

// PutMulti creates or updates package mappings for multiple binary package names.
func (s *UbuntuPackageMappingStore) PutMulti(ctx context.Context, mappings []*models.UbuntuPackageMapping) error {
	for chunk := range slices.Chunk(mappings, maxDatastorePutMultiBatchSize) {
		keys := make([]*datastore.Key, 0, len(chunk))
		entities := make([]*ubuntuPackageMappingEntity, 0, len(chunk))
		for _, m := range chunk {
			if m == nil {
				continue
			}
			keys = append(keys, datastore.NameKey(UbuntuPackageMappingKind, m.BinaryName, nil))
			entities = append(entities, &ubuntuPackageMappingEntity{
				SourceNames: m.SourceNames,
			})
		}
		if len(keys) == 0 {
			continue
		}

		if _, err := s.client.PutMulti(ctx, keys, entities); err != nil {
			return fmt.Errorf("failed to put multi UbuntuPackageMapping: %w", err)
		}
	}

	return nil
}
