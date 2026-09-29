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
	"time"

	"cloud.google.com/go/datastore"
	"github.com/google/osv.dev/go/internal/models"
)

const jobDataKind = "JobData"

type jobDataEntity[T any] struct {
	Value T `datastore:"value,noindex"`
}

type JobDataStore struct {
	client *datastore.Client
}

var _ models.JobDataStore = (*JobDataStore)(nil)

func NewJobDataStore(client *datastore.Client) *JobDataStore {
	return &JobDataStore{client: client}
}

func getJobData[T any](ctx context.Context, client *datastore.Client, key string, dst *T) error {
	if dst == nil {
		return fmt.Errorf("%w: dst cannot be nil", models.ErrInvalidArgument)
	}
	var entity jobDataEntity[T]
	if err := client.Get(ctx, datastore.NameKey(jobDataKind, key, nil), &entity); err != nil {
		if errors.Is(err, datastore.ErrNoSuchEntity) {
			return models.ErrNotFound
		}

		return fmt.Errorf("failed to get JobData %s: %w", key, err)
	}
	*dst = entity.Value

	return nil
}

func setJobData[T any](ctx context.Context, client *datastore.Client, key string, val T) error {
	entity := jobDataEntity[T]{Value: val}
	if _, err := client.Put(ctx, datastore.NameKey(jobDataKind, key, nil), &entity); err != nil {
		return fmt.Errorf("failed to put JobData %s: %w", key, err)
	}

	return nil
}

func (s *JobDataStore) Get(ctx context.Context, key string, dst any) error {
	switch d := dst.(type) {
	case *time.Time:
		return getJobData(ctx, s.client, key, d)
	case *[]string:
		return getJobData(ctx, s.client, key, d)
	default:
		return fmt.Errorf("%w: unsupported JobData destination type %T", models.ErrInvalidArgument, dst)
	}
}

func (s *JobDataStore) Set(ctx context.Context, key string, val any) error {
	switch v := val.(type) {
	case time.Time:
		return setJobData(ctx, s.client, key, v.UTC())
	case []string:
		return setJobData(ctx, s.client, key, v)
	default:
		return fmt.Errorf("%w: unsupported JobData value type %T", models.ErrInvalidArgument, val)
	}
}
