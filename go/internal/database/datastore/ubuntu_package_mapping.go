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

	"cloud.google.com/go/datastore"
	"github.com/google/osv.dev/go/internal/models"
)

const (
	UbuntuPackageMappingKind = "UbuntuPackageMapping"

	maxDatastoreGetMultiBatchSize = 1000
	maxDatastorePutMultiBatchSize = 500
)

type ubuntuPackageMappingEntity struct {
	SourceNames []string `datastore:"source_names"`
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
	if len(binaryNames) == 0 {
		return []*models.UbuntuPackageMapping{}, nil
	}

	results := make([]*models.UbuntuPackageMapping, len(binaryNames))

	for i := 0; i < len(binaryNames); i += maxDatastoreGetMultiBatchSize {
		end := min(i+maxDatastoreGetMultiBatchSize, len(binaryNames))
		chunkNames := binaryNames[i:end]

		keys := make([]*datastore.Key, len(chunkNames))
		entities := make([]*ubuntuPackageMappingEntity, len(chunkNames))
		for j, name := range chunkNames {
			keys[j] = datastore.NameKey(UbuntuPackageMappingKind, name, nil)
		}

		err := s.client.GetMulti(ctx, keys, entities)
		if err != nil {
			if multiErr, ok := errors.AsType[datastore.MultiError](err); ok {
				for j, e := range multiErr {
					if errors.Is(e, datastore.ErrNoSuchEntity) {
						entities[j] = nil
					} else if e != nil {
						return nil, fmt.Errorf("failed to get multi UbuntuPackageMapping: %w", err)
					}
				}
			} else {
				return nil, fmt.Errorf("failed to get multi UbuntuPackageMapping: %w", err)
			}
		}

		for j, name := range chunkNames {
			mapping := &models.UbuntuPackageMapping{
				BinaryName:  name,
				SourceNames: []string{},
			}
			if j < len(entities) && entities[j] != nil && len(entities[j].SourceNames) > 0 {
				mapping.SourceNames = entities[j].SourceNames
			}
			results[i+j] = mapping
		}
	}

	return results, nil
}

// PutMulti creates or updates package mappings for multiple binary package names.
func (s *UbuntuPackageMappingStore) PutMulti(ctx context.Context, mappings []*models.UbuntuPackageMapping) error {
	if len(mappings) == 0 {
		return nil
	}

	for i := 0; i < len(mappings); i += maxDatastorePutMultiBatchSize {
		end := min(i+maxDatastorePutMultiBatchSize, len(mappings))
		chunk := mappings[i:end]

		keys := make([]*datastore.Key, len(chunk))
		entities := make([]*ubuntuPackageMappingEntity, len(chunk))
		for j, m := range chunk {
			keys[j] = datastore.NameKey(UbuntuPackageMappingKind, m.BinaryName, nil)
			sourceNames := m.SourceNames
			if sourceNames == nil {
				sourceNames = []string{}
			}
			entities[j] = &ubuntuPackageMappingEntity{
				SourceNames: sourceNames,
			}
		}

		if _, err := s.client.PutMulti(ctx, keys, entities); err != nil {
			return fmt.Errorf("failed to put multi UbuntuPackageMapping: %w", err)
		}
	}

	return nil
}
