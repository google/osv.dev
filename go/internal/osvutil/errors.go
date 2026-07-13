package osvutil

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// IsContextError returns true if the error is due to context cancellation or deadline expiration
// (either standard Go context errors or gRPC status errors).
func IsContextError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	// Context cancellation during a gRPC call returns a gRPC status error rather than a standard context error.
	// Check the gRPC status code directly (returns codes.Unknown if err is not a gRPC status error).
	code := status.Code(err)

	return code == codes.Canceled || code == codes.DeadlineExceeded
}
