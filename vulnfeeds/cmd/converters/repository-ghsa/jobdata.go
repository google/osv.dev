// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
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
	"sync"
	"time"

	"cloud.google.com/go/datastore"
)

const (
	// jobDataKind is the Datastore entity kind for job metadata.
	jobDataKind = "JobData"
	// defaultJobDataKey is the default entity ID in Datastore for this cron job.
	defaultJobDataKey = "repository_ghsa_last_run"
)

// jobDataLastRunEntity mirrors the Datastore JobData entity schema used across osv.dev.
type jobDataLastRunEntity struct {
	Value *time.Time `datastore:"value,noindex"`
}

// JobDataStore abstracts storage operations for job execution metadata.
type JobDataStore interface {
	GetLastRun(ctx context.Context, jobID string) (*time.Time, error)
	SetLastRun(ctx context.Context, jobID string, t time.Time) error
	Close() error
}

// DatastoreJobStore implements JobDataStore using Google Cloud Datastore.
type DatastoreJobStore struct {
	client *datastore.Client
}

// NewDatastoreJobStore creates a new DatastoreJobStore for the given GCP project.
func NewDatastoreJobStore(ctx context.Context, projectID string) (*DatastoreJobStore, error) {
	client, err := datastore.NewClient(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("datastore.NewClient: %w", err)
	}

	return &DatastoreJobStore{client: client}, nil
}

// GetLastRun retrieves the last execution timestamp for the given job ID.
func (s *DatastoreJobStore) GetLastRun(ctx context.Context, jobID string) (*time.Time, error) {
	key := datastore.NameKey(jobDataKind, jobID, nil)
	var entity jobDataLastRunEntity
	err := s.client.Get(ctx, key, &entity)
	if err != nil {
		if errors.Is(err, datastore.ErrNoSuchEntity) {
			//nolint:nilnil // A nil pointer with nil error signifies that no prior execution record exists.
			return nil, nil
		}

		return nil, fmt.Errorf("failed to get %s from Datastore: %w", jobID, err)
	}

	return entity.Value, nil
}

// SetLastRun records the execution timestamp for the given job ID.
func (s *DatastoreJobStore) SetLastRun(ctx context.Context, jobID string, t time.Time) error {
	key := datastore.NameKey(jobDataKind, jobID, nil)
	utcTime := t.UTC()
	entity := jobDataLastRunEntity{Value: &utcTime}
	_, err := s.client.Put(ctx, key, &entity)
	if err != nil {
		return fmt.Errorf("failed to write %s to Datastore: %w", jobID, err)
	}

	return nil
}

// Close closes the underlying Datastore client.
func (s *DatastoreJobStore) Close() error {
	if s.client != nil {
		return s.client.Close()
	}

	return nil
}

// MemJobStore implements JobDataStore in-memory for testing and dry-run executions.
type MemJobStore struct {
	mu   sync.RWMutex
	data map[string]time.Time
}

// NewMemJobStore creates a new in-memory JobDataStore.
func NewMemJobStore() *MemJobStore {
	return &MemJobStore{
		data: make(map[string]time.Time),
	}
}

// GetLastRun retrieves the timestamp from memory.
func (m *MemJobStore) GetLastRun(_ context.Context, jobID string) (*time.Time, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.data[jobID]
	if !ok {
		//nolint:nilnil // A nil pointer with nil error signifies that no prior execution record exists.
		return nil, nil
	}
	tCopy := t.UTC()

	return &tCopy, nil
}

// SetLastRun stores the timestamp in memory.
func (m *MemJobStore) SetLastRun(_ context.Context, jobID string, t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[jobID] = t.UTC()

	return nil
}

// Close is a no-op for MemJobStore.
func (m *MemJobStore) Close() error {
	return nil
}
