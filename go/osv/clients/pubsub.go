package clients

import (
	"context"

	"cloud.google.com/go/pubsub/v2"
)

// PublishResult is an interface for the result of a publish operation.
type PublishResult interface {
	Get(ctx context.Context) (string, error)
}

// Publisher is an interface for publishing messages.
type Publisher interface {
	Publish(ctx context.Context, msg *pubsub.Message) PublishResult
}

// GCPPublisher is a wrapper around the concrete GCP Pub/Sub Publisher.
type GCPPublisher struct {
	Publisher *pubsub.Publisher
}

func (p *GCPPublisher) Publish(ctx context.Context, msg *pubsub.Message) PublishResult {
	return &GCPPublishResult{Result: p.Publisher.Publish(ctx, msg)}
}

// GCPPublishResult is a wrapper around the concrete GCP Pub/Sub PublishResult.
type GCPPublishResult struct {
	Result *pubsub.PublishResult
}

func (r *GCPPublishResult) Get(ctx context.Context) (string, error) {
	return r.Result.Get(ctx)
}
