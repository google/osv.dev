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

// Package batcher implements a generic, thread-safe auto-batching utility.
// It allows grouping multiple individual concurrent requests into a single batch
// operation (e.g. database GetMulti) to reduce network roundtrips and improve performance.
//
// It handles queueing, concurrency, leader-follower synchronization, early triggering
// (when the batch reaches a maximum size), timeout-based triggering, and context merging
// (ensuring the batch is only cancelled if all individual participant contexts are cancelled,
// while allowing cancelled requests to return immediately).
package batcher

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Result wraps the value and error returned for a single key in the batch.
type Result[R any] struct {
	Val R
	Err error
}

// BatchFunc defines the signature of the function that processes the batch.
// It must return a slice of Results of the same length as the input keys,
// where results[i] corresponds to keys[i].
type BatchFunc[K any, R any] func(ctx context.Context, keys []K) []Result[R]

//nolint:containedctx // context is needed to merge them in the batch worker
type request[K any, R any] struct {
	key        K
	ctx        context.Context
	resultChan chan Result[R]
}

// Batcher orchestrates the auto-batching of individual concurrent requests.
//
// How it works (The Concurrency Model):
//
//  1. Queueing:
//     When a goroutine calls Get(ctx, key), it creates a private request object
//     containing a result channel and appends it to the shared `pending` slice.
//
// 2. Leader Election:
//
//   - The goroutine that appends the FIRST request to a new batch becomes the "leader" (isLeader == true).
//
//   - The leader goroutine is responsible for spawning a background worker goroutine (runBatchLoop)
//     to process the batch.
//
//   - Subsequent goroutines ("followers") just append their requests and block, waiting for the leader's worker.
//
//     3. Triggering:
//     The background worker (runBatchLoop) waits to process the batch until either:
//
//   - The `timeout` (e.g. 1ms) expires (time-based triggering).
//
//   - The batch reaches `maxSize` elements, which sends a signal to `triggerChan` (size-based triggering).
//
//     4. Processing & Context Merging:
//     Once triggered, the worker:
//
//   - Locks the batcher, steals the `pending` slice, and resets it to nil (so new requests start a new batch).
//
//   - Filters out any requests whose contexts were already cancelled while waiting in the queue.
//
//   - Merges the contexts of all remaining active requests into a single `mergedCtx` using `mergeContexts`.
//     This ensures the batch database call is only aborted if ALL individual callers abort.
//
//   - Calls the user-provided `BatchFunc` with the merged context and the list of keys.
//
//     5. Distribution:
//     The worker receives the results from `BatchFunc` and distributes them back to each caller's
//     individual `resultChan`.
//
//     6. Caller Synchronization & Cancellation:
//     Meanwhile, the caller goroutines (both leader and followers) are blocked on a select statement,
//     waiting for either:
//
//   - Their result to arrive on `resultChan` (success/error from the worker).
//
//   - Their individual `ctx.Done()` to fire (cancellation/timeout). If a caller's context is cancelled,
//     they return immediately to their user, without waiting for the batch to finish.
//
// Note: This batcher does not recover from panics in BatchFunc.
// If reusing this for complex/input-dependent logic, consider adding recover() in runBatchLoop.
type Batcher[K any, R any] struct {
	mu          sync.Mutex
	pending     []*request[K, R]
	timeout     time.Duration
	maxSize     int
	triggerChan chan struct{}
	batchFunc   BatchFunc[K, R]
}

// New creates a new Batcher.
func New[K any, R any](timeout time.Duration, maxSize int, batchFunc BatchFunc[K, R]) *Batcher[K, R] {
	if timeout == 0 {
		timeout = 1 * time.Millisecond
	}
	if maxSize == 0 {
		maxSize = 100
	}

	return &Batcher[K, R]{
		timeout:     timeout,
		maxSize:     maxSize,
		triggerChan: make(chan struct{}, 1),
		batchFunc:   batchFunc,
	}
}

// Get enqueues a request and waits for the batch to complete or context cancellation.
func (b *Batcher[K, R]) Get(ctx context.Context, key K) (R, error) {
	var zero R
	if err := ctx.Err(); err != nil {
		return zero, err
	}

	req := &request[K, R]{
		key: key,
		ctx: ctx,
		// Buffered to capacity 1 to prevent the background worker from blocking
		// if this caller's context is cancelled and they exit Get() early.
		resultChan: make(chan Result[R], 1),
	}

	b.mu.Lock()
	b.pending = append(b.pending, req)
	isLeader := len(b.pending) == 1

	if len(b.pending) >= b.maxSize {
		// Signal the worker to trigger early because we reached the max size.
		select {
		case b.triggerChan <- struct{}{}:
		default:
		}
	}
	b.mu.Unlock()

	if isLeader {
		// The leader spawns the background worker to process this batch.
		go b.runBatchLoop()
	}

	// Block until either the worker sends us the result, or our individual context is cancelled.
	select {
	case res := <-req.resultChan:
		return res.Val, res.Err
	case <-ctx.Done():
		return zero, ctx.Err()
	}
}

func (b *Batcher[K, R]) runBatchLoop() {
	// Wait for the batch to fill up or the timeout to expire.
	select {
	case <-time.After(b.timeout):
	case <-b.triggerChan:
	}

	b.mu.Lock()
	batch := b.pending
	b.pending = nil // Reset pending so the next request starts a new batch.
	// Drain triggerChan to avoid stale triggers for the next batch.
	select {
	case <-b.triggerChan:
	default:
	}
	b.mu.Unlock()

	if len(batch) == 0 {
		return
	}

	validRequests := make([]*request[K, R], 0, len(batch))
	subCtxs := make([]context.Context, 0, len(batch))

	// Filter out requests that were already cancelled while waiting in the queue.
	for _, req := range batch {
		if req.ctx.Err() == nil {
			validRequests = append(validRequests, req)
			subCtxs = append(subCtxs, req.ctx)
		} else {
			// Notify the cancelled caller (though they might have already returned).
			req.resultChan <- Result[R]{Err: req.ctx.Err()}
		}
	}

	if len(validRequests) == 0 {
		return
	}

	// Merge the contexts of all active requests.
	mergedCtx, cancel := mergeContexts(subCtxs)
	defer cancel()

	keys := make([]K, len(validRequests))
	for i, req := range validRequests {
		keys[i] = req.key
	}

	// Execute the user-provided batch function.
	results := b.batchFunc(mergedCtx, keys)

	// Safety check: ensure batchFunc returned correct number of results.
	if len(results) != len(validRequests) {
		err := errors.New("batcher: batchFunc returned unexpected number of results")
		for _, req := range validRequests {
			req.resultChan <- Result[R]{Err: err}
		}

		return
	}

	// Distribute results back to callers.
	for i, req := range validRequests {
		req.resultChan <- results[i]
	}
}
