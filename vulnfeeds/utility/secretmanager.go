package utility

import (
	"context"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

// GetSecret retrieves the named Cloud Secret version.
// It returns the contents of the secret as a string.
func GetSecret(secretVersion string) (secret string, err error) {
	ctx := context.Background()
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return "", err
	}
	defer client.Close()

	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: secretVersion,
	}

	resp, err := client.AccessSecretVersion(ctx, req)

	if err != nil {
		return "", err
	}

	return string(resp.Payload.Data), nil
}
