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

package osvutil

import (
	"context"
	"testing"
	"time"
)

func TestMergeContexts_AllCancelled(t *testing.T) {
	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())

	mergedCtx, cancelMerged := MergeContexts([]context.Context{ctx1, ctx2})
	defer cancelMerged()

	cancel1()
	// Merged context should still be active because ctx2 is active
	select {
	case <-mergedCtx.Done():
		t.Fatalf("Merged context cancelled prematurely")
	default:
	}

	cancel2()
	// Now both are cancelled, merged context should be cancelled
	select {
	case <-mergedCtx.Done():
		// Success
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("Merged context was not cancelled after all sub-contexts cancelled")
	}
}

func TestMergeContexts_ManualCancel(t *testing.T) {
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()

	mergedCtx, cancelMerged := MergeContexts([]context.Context{ctx1})

	cancelMerged() // Cancel manually
	select {
	case <-mergedCtx.Done():
		// Success
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("Merged context was not cancelled after manual cancel")
	}
}

func TestMergeContexts_EmptyList(t *testing.T) {
	mergedCtx, cancelMerged := MergeContexts([]context.Context{})
	defer cancelMerged()

	select {
	case <-mergedCtx.Done():
		// Success
	default:
		t.Fatalf("Merged context with empty list should be cancelled immediately")
	}
}
