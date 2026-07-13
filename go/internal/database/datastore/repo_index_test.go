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
	"testing"

	"github.com/google/osv.dev/go/internal/osvutil/safe"
)

func TestRepoIndexStore_QueryBucketsPanicPropagation(t *testing.T) {
	ctx := context.Background()

	// Initialize the store with a nil client.
	// Any call to s.client.GetAll inside the errgroup tasks will trigger a nil-pointer panic.
	store := NewRepoIndexStore(nil)

	// Trigger QueryBuckets with some mock node hashes
	_, err := store.QueryBuckets(ctx, [][]byte{
		{0xab, 0xcd},
		{0x12, 0x34},
	})

	if err == nil {
		t.Fatalf("Expected error due to nil-pointer panic, got nil")
	}

	// Verify that the panic was recovered and returned as a *safe.PanicError
	var panicErr *safe.PanicError
	if !errors.As(err, &panicErr) {
		t.Fatalf("Expected error to be *safe.PanicError, got %T: %v", err, err)
	}

	// The panic value should indicate a nil pointer dereference (runtime error)
	if panicErr.Value == nil {
		t.Errorf("Expected non-nil panic value")
	}

	if len(panicErr.Stack) == 0 {
		t.Errorf("Expected stack trace to be populated, got empty")
	}

	t.Logf("Successfully recovered and propagated nil-pointer panic from errgroup: %v", panicErr)
}
