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

package batcher

import (
	"context"
	"sync/atomic"
)

// mergeContexts returns a context that is cancelled ONLY when ALL of the provided
// sub-contexts are cancelled.
//
// The returned CancelFunc MUST be called to clean up resources once the operation
// using the merged context completes.
func mergeContexts(subCtxs []context.Context) (context.Context, context.CancelFunc) {
	mergedCtx, cancel := context.WithCancel(context.Background())

	if len(subCtxs) == 0 {
		cancel()
		return mergedCtx, cancel
	}

	var activeCount atomic.Int64
	activeCount.Store(int64(len(subCtxs)))

	for _, ctx := range subCtxs {
		go func(c context.Context) {
			select {
			case <-c.Done():
				// This sub-context was cancelled.
				// Decrement count; if it reaches 0, cancel the merged context.
				if activeCount.Add(-1) == 0 {
					cancel()
				}
			case <-mergedCtx.Done():
				// The merged operation completed (or was cancelled manually).
				// Exit the goroutine to prevent leaks.
				return
			}
		}(ctx)
	}

	return mergedCtx, cancel
}
