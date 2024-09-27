package faulttolerant

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/sethvargo/go-retry"
)

// Make a HTTP GET request for url and retry 3 times, with an exponential backoff.
func Get(url string) (resp *http.Response, err error) {
	backoff := retry.NewExponential(1 * time.Second)
	if err := retry.Do(context.Background(), retry.WithMaxRetries(3, backoff), func(ctx context.Context) error {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return err
		}

		r, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}

		switch r.StatusCode / 100 {
		case 4:
			return fmt.Errorf("bad response: %v", r.StatusCode)
		case 5:
			return retry.RetryableError(fmt.Errorf("bad response: %v", r.StatusCode))
		default:
			resp = r
			return nil
		}
	}); err != nil {
		return nil, fmt.Errorf("fail: %q: %v", url, err)
	}
	return resp, err
}

// Make a HTTP HEAD request for url and retry 3 times, with an exponential backoff.
func Head(url string) (resp *http.Response, err error) {
	backoff := retry.NewExponential(1 * time.Second)
	if err := retry.Do(context.Background(), retry.WithMaxRetries(3, backoff), func(ctx context.Context) error {
		req, err := http.NewRequest("HEAD", url, nil)
		if err != nil {
			return err
		}

		r, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer r.Body.Close()

		switch r.StatusCode / 100 {
		case 4:
			return fmt.Errorf("bad response: %v", r.StatusCode)
		case 5:
			return retry.RetryableError(fmt.Errorf("bad response: %v", r.StatusCode))
		default:
			resp = r
			return nil
		}
	}); err != nil {
		return nil, fmt.Errorf("fail: %q: %v", url, err)
	}
	return resp, err
}
