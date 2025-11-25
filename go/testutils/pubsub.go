package testutils

import (
	"context"
	"sync"

	"cloud.google.com/go/pubsub/v2"
	"github.com/google/osv.dev/go/osv/clients"
)

type MockPublishResult struct {
	msgID string
	err   error
}

func (r *MockPublishResult) Get(ctx context.Context) (string, error) {
	return r.msgID, r.err
}

type MockPublisher struct {
	mu       sync.Mutex
	Messages []*pubsub.Message
}

func (p *MockPublisher) Publish(ctx context.Context, msg *pubsub.Message) clients.PublishResult {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Messages = append(p.Messages, msg)
	return &MockPublishResult{msgID: "mock-msg-id", err: nil}
}
