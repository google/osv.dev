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

func makeDatastoreKey(ecosystem, binaryName string) *datastore.Key {
	normalizedEco := models.NormalizeUbuntuEcosystem(ecosystem)
	return datastore.NameKey(UbuntuPackageMappingKind, normalizedEco+":"+binaryName, nil)
}

// GetMulti retrieves mappings for a slice of (ecosystem, binary_name) keys.
// Any key not found in Datastore will return an UbuntuPackageMapping with an empty SourceNames slice.
func (s *UbuntuPackageMappingStore) GetMulti(ctx context.Context, pkgKeys []models.UbuntuPackageKey) ([]*models.UbuntuPackageMapping, error) {
	results := make([]*models.UbuntuPackageMapping, 0, len(pkgKeys))

	for chunkKeys := range slices.Chunk(pkgKeys, maxDatastoreGetMultiBatchSize) {
		dsKeys := make([]*datastore.Key, len(chunkKeys))
		entities := make([]*ubuntuPackageMappingEntity, len(chunkKeys))
		for j, k := range chunkKeys {
			dsKeys[j] = makeDatastoreKey(k.Ecosystem, k.BinaryName)
		}

		if err := s.client.GetMulti(ctx, dsKeys, entities); err != nil {
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

		for j, k := range chunkKeys {
			sourceNames := []string{}
			if entities[j] != nil && len(entities[j].SourceNames) > 0 {
				sourceNames = entities[j].SourceNames
			}
			results = append(results, &models.UbuntuPackageMapping{
				Ecosystem:   models.NormalizeUbuntuEcosystem(k.Ecosystem),
				BinaryName:  k.BinaryName,
				SourceNames: sourceNames,
			})
		}
	}

	return results, nil
}

// PutMulti creates or updates package mappings for multiple (ecosystem, binary_name) pairs.
func (s *UbuntuPackageMappingStore) PutMulti(ctx context.Context, mappings []*models.UbuntuPackageMapping) error {
	for chunk := range slices.Chunk(mappings, maxDatastorePutMultiBatchSize) {
		dsKeys := make([]*datastore.Key, 0, len(chunk))
		entities := make([]*ubuntuPackageMappingEntity, 0, len(chunk))
		for _, m := range chunk {
			if m == nil {
				continue
			}
			dsKeys = append(dsKeys, makeDatastoreKey(m.Ecosystem, m.BinaryName))
			entities = append(entities, &ubuntuPackageMappingEntity{
				SourceNames: m.SourceNames,
			})
		}
		if len(dsKeys) == 0 {
			continue
		}

		if _, err := s.client.PutMulti(ctx, dsKeys, entities); err != nil {
			return fmt.Errorf("failed to put multi UbuntuPackageMapping: %w", err)
		}
	}

	return nil
}
