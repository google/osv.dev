package main

import (
	"context"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestConcurrencyLimit(t *testing.T) {
	// Save original
	originalFetchBlob := fetchBlob
	originalSemaphore := semaphore
	defer func() {
		fetchBlob = originalFetchBlob
		semaphore = originalSemaphore
	}()

	// Mock fetchBlob
	fetchBlob = func(ctx context.Context, url string, forceUpdate bool) ([]byte, error) {
		time.Sleep(200 * time.Millisecond)
		return []byte("mock data"), nil
	}

	// Set limit to 1
	semaphore = make(chan struct{}, 1)

	// We need a waitgroup
	var wg sync.WaitGroup
	wg.Add(2)

	start := time.Now()

	// Launch 2 requests
	go func() {
		defer wg.Done()
		req := httptest.NewRequest("GET", "/getgit?url=https://github.com/google/osv.dev-1.git&force-update=true", nil)
		w := httptest.NewRecorder()
		gitHandler(w, req)
	}()

	go func() {
		defer wg.Done()
		// Small delay ensuring 1st starts first
		time.Sleep(10 * time.Millisecond)
		req := httptest.NewRequest("GET", "/getgit?url=https://github.com/google/osv.dev-2.git&force-update=true", nil)
		w := httptest.NewRecorder()
		gitHandler(w, req)
	}()

	wg.Wait()
	duration := time.Since(start)

	// Expectation: 200ms + 200ms = 400ms.
	// Allow some slack, say > 300ms.
	if duration < 300*time.Millisecond {
		t.Errorf("Expected sequential execution (> 300ms), got %v", duration)
	}
}
