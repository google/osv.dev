package faulttolerant

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/sethvargo/go-retry"
)

// Get makes a HTTP GET request for url and retry 3 times, with an exponential backoff.
func Get(url string) (resp *http.Response, err error) {
	return req(url, "GET")
}

// Head makes a HTTP HEAD request for url and retry 3 times, with an exponential backoff.
func Head(url string) (resp *http.Response, err error) {
	return req(url, "HEAD")
}

// Get makes a HTTP GET request for url and retry 3 times, with an exponential backoff.
func req(url, method string) (resp *http.Response, err error) {
	backoff := retry.NewExponential(1 * time.Second)
	if err := retry.Do(context.Background(), retry.WithMaxRetries(3, backoff), func(ctx context.Context) error {
		req, err := http.NewRequest(method, url, nil)
		if err != nil {
			return err
		}

		r, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}

		switch r.StatusCode / 100 {
		case 4:
			r.Body.Close()
			return fmt.Errorf("bad response: %v", r.StatusCode)
		case 5:
			r.Body.Close()
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
