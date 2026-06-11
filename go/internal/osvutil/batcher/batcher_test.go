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
	"errors"
	"sync"
	"testing"
	"time"
)

func TestBatcher_Get(t *testing.T) {
	ctx := context.Background()

	// A simple batch function that converts string keys to uppercase
	batchFunc := func(_ context.Context, keys []string) []Result[string] {
		results := make([]Result[string], len(keys))
		for i, key := range keys {
			if key == "error" {
				results[i] = Result[string]{Err: errors.New("triggered error")}
			} else {
				results[i] = Result[string]{Val: "UP_" + key}
			}
		}

		return results
	}

	b := New(10*time.Millisecond, 100, batchFunc)

	var wg sync.WaitGroup
	wg.Add(3)

	var res1, res2 string
	var err1, err2, err3 error

	go func() {
		defer wg.Done()
		res1, err1 = b.Get(ctx, "hello")
	}()

	go func() {
		defer wg.Done()
		res2, err2 = b.Get(ctx, "world")
	}()

	go func() {
		defer wg.Done()
		_, err3 = b.Get(ctx, "error")
	}()

	wg.Wait()

	if err1 != nil {
		t.Errorf("Unexpected error for 'hello': %v", err1)
	} else if res1 != "UP_hello" {
		t.Errorf("Expected 'UP_hello', got '%s'", res1)
	}

	if err2 != nil {
		t.Errorf("Unexpected error for 'world': %v", err2)
	} else if res2 != "UP_world" {
		t.Errorf("Expected 'UP_world', got '%s'", res2)
	}

	if err3 == nil || err3.Error() != "triggered error" {
		t.Errorf("Expected 'triggered error', got %v", err3)
	}
}

func TestBatcher_TriggerEarly(t *testing.T) {
	ctx := context.Background()

	var batchCount int
	var mu sync.Mutex

	batchFunc := func(_ context.Context, keys []int) []Result[int] {
		mu.Lock()
		batchCount++
		mu.Unlock()
		results := make([]Result[int], len(keys))
		for i, key := range keys {
			results[i] = Result[int]{Val: key * 2}
		}

		return results
	}

	// Set a long timeout but small max size to trigger early
	b := New(10*time.Second, 3, batchFunc)

	start := time.Now()

	var wg sync.WaitGroup
	wg.Add(3)

	var res1, res2, res3 int
	var err1, err2, err3 error

	go func() {
		defer wg.Done()
		res1, err1 = b.Get(ctx, 1)
	}()

	go func() {
		defer wg.Done()
		res2, err2 = b.Get(ctx, 2)
	}()

	// Give it a tiny bit of time to ensure the first two are registered
	time.Sleep(10 * time.Millisecond)

	go func() {
		defer wg.Done()
		res3, err3 = b.Get(ctx, 3) // This should trigger the batch of 3 early
	}()

	wg.Wait()

	duration := time.Since(start)
	if duration > 2*time.Second {
		t.Errorf("Batch took too long (%v), expected early trigger", duration)
	}

	if err1 != nil || res1 != 2 {
		t.Errorf("Unexpected result 1: res=%d, err=%v", res1, err1)
	}
	if err2 != nil || res2 != 4 {
		t.Errorf("Unexpected result 2: res=%d, err=%v", res2, err2)
	}
	if err3 != nil || res3 != 6 {
		t.Errorf("Unexpected result 3: res=%d, err=%v", res3, err3)
	}

	mu.Lock()
	if batchCount != 1 {
		t.Errorf("Expected 1 batch execution, got %d", batchCount)
	}
	mu.Unlock()
}

func TestBatcher_Cancellation(t *testing.T) {
	// We want to test that if a request is cancelled, it returns immediately
	// and doesn't block the rest of the batch.

	sem := make(chan struct{})
	batchFunc := func(_ context.Context, keys []string) []Result[string] {
		// Block inside the batch function until we signal it to proceed.
		// This simulates a slow database call.
		<-sem
		results := make([]Result[string], len(keys))
		for i, key := range keys {
			results[i] = Result[string]{Val: "OK_" + key}
		}

		return results
	}

	b := New(10*time.Millisecond, 2, batchFunc)

	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2 := context.Background()

	var wg sync.WaitGroup
	wg.Add(2)

	var res2 string
	var err1, err2 error

	start := time.Now()

	go func() {
		defer wg.Done()
		_, err1 = b.Get(ctx1, "cancel-me")
	}()

	go func() {
		defer wg.Done()
		res2, err2 = b.Get(ctx2, "keep-me")
	}()

	// Give it a tiny bit of time to get queued
	time.Sleep(5 * time.Millisecond)

	// Cancel the first request
	cancel1()

	// Request 1 should return immediately because it was cancelled
	// We check if the goroutine for req1 finished quickly
	c1Done := make(chan struct{})
	go func() {
		wg.Wait() // This waits for both, but we want to see if we can progress
		close(c1Done)
	}()

	select {
	case <-c1Done:
		t.Fatalf("Both finished, but batchFunc was blocked, so cancel1 didn't return immediately")
	case <-time.After(50 * time.Millisecond):
		// Expected: c1Done is NOT closed yet because req2 is still blocked in batchFunc
	}

	// But req1 itself should have returned. We can't easily check individual goroutine status,
	// but we can verify that if we now unblock the batch, req1 got the cancel error and req2 got the success.
	close(sem) // Unblock the batch function

	<-c1Done // Now both should finish

	if !errors.Is(err1, context.Canceled) {
		t.Errorf("Expected context.Canceled for req1, got %v", err1)
	}

	if err2 != nil || res2 != "OK_keep-me" {
		t.Errorf("Expected success for req2, got res=%q, err=%v", res2, err2)
	}

	t.Logf("Total time: %v", time.Since(start))
}
