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

// Package jsonstore provides an in-memory implementation of models.UbuntuPackageMappingStore
// that optionally persists state to and loads from a JSON file.
package jsonstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/google/osv.dev/go/internal/models"
)

// JSONStore is an in-memory store backed by an optional JSON file on disk.
type JSONStore struct {
	mu       sync.RWMutex
	filePath string
	mappings map[string]map[string][]string
}

var _ models.UbuntuPackageMappingStore = (*JSONStore)(nil)

// New creates a new JSONStore. If filePath is non-empty and the file exists,
// it loads existing data from the file into memory. If the file does not exist,
// an empty store is created and will be written to filePath on modifications.
// If filePath is empty, the store operates entirely in-memory.
func New(filePath string) (*JSONStore, error) {
	store := &JSONStore{
		filePath: filePath,
		mappings: make(map[string]map[string][]string),
	}

	if filePath == "" {
		return store, nil
	}

	dataBytes, err := os.ReadFile(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return store, nil
		}

		return nil, fmt.Errorf("failed reading JSON store file %s: %w", filePath, err)
	}

	if len(dataBytes) == 0 {
		return store, nil
	}

	var mappings map[string]map[string][]string
	if err := json.Unmarshal(dataBytes, &mappings); err != nil {
		return nil, fmt.Errorf("failed unmarshaling JSON store file %s: %w", filePath, err)
	}

	if mappings != nil {
		store.mappings = mappings
	}

	return store, nil
}

// GetMulti retrieves package mappings for multiple (ecosystem, binary_name) keys.
func (s *JSONStore) GetMulti(_ context.Context, keys []models.UbuntuPackageKey) ([]*models.UbuntuPackageMapping, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	results := make([]*models.UbuntuPackageMapping, len(keys))
	for i, k := range keys {
		eco := models.NormalizeUbuntuEcosystem(k.Ecosystem)
		var srcs []string
		if ecoMap, ok := s.mappings[eco]; ok {
			srcs = ecoMap[k.BinaryName]
		}
		if srcs == nil {
			srcs = []string{}
		}
		results[i] = &models.UbuntuPackageMapping{
			Ecosystem:   eco,
			BinaryName:  k.BinaryName,
			SourceNames: slices.Clone(srcs),
		}
	}

	return results, nil
}

// PutMulti stores or updates mappings for multiple (ecosystem, binary_name) pairs.
func (s *JSONStore) PutMulti(_ context.Context, mappings []*models.UbuntuPackageMapping) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, item := range mappings {
		if item == nil {
			continue
		}
		eco := models.NormalizeUbuntuEcosystem(item.Ecosystem)
		if s.mappings[eco] == nil {
			s.mappings[eco] = make(map[string][]string)
		}
		srcs := slices.Clone(item.SourceNames)
		slices.Sort(srcs)
		s.mappings[eco][item.BinaryName] = slices.Compact(srcs)
	}

	if s.filePath == "" {
		return nil
	}

	dir := filepath.Dir(s.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed creating directory %s: %w", dir, err)
	}

	bytes, err := json.MarshalIndent(s.mappings, "", "  ")
	if err != nil {
		return fmt.Errorf("failed marshaling JSON store: %w", err)
	}
	bytes = append(bytes, '\n')

	tmpFile := s.filePath + ".tmp"
	if err := os.WriteFile(tmpFile, bytes, 0600); err != nil {
		return fmt.Errorf("failed writing temporary JSON file %s: %w", tmpFile, err)
	}

	if err := os.Rename(tmpFile, s.filePath); err != nil {
		return fmt.Errorf("failed renaming %s to %s: %w", tmpFile, s.filePath, err)
	}

	return nil
}
