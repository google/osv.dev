package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"cloud.google.com/go/datastore"
	"cloud.google.com/go/logging"
	"cloud.google.com/go/pubsub"
	"cloud.google.com/go/storage"
	"github.com/google/osv.dev/go/models"
	"google.golang.org/api/iterator"
)

// appEnv holds the clients and other environment-specific resources.
type appEnv struct {
	logger *logging.Logger
	bucket *storage.BucketHandle
	ds     *datastore.Client
	topic  *pubsub.Topic
}

// setup initializes the application environment.
func setup(ctx context.Context) (*appEnv, error) {
	projectID, ok := os.LookupEnv("GOOGLE_CLOUD_PROJECT")
	if !ok {
		return nil, errors.New("GOOGLE_CLOUD_PROJECT must be set")
	}

	logger, err := setupLogging(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to setup logging: %w", err)
	}

	bucketName, ok := os.LookupEnv("OSV_VULNERABILITIES_BUCKET")
	if !ok {
		err := errors.New("OSV_VULNERABILITIES_BUCKET must be set")
		logger.Log(logging.Entry{Severity: logging.Critical, Payload: err.Error()})
		return nil, err
	}
	stClient, err := storage.NewClient(ctx)
	if err != nil {
		err = fmt.Errorf("failed to create storage client: %w", err)
		logger.Log(logging.Entry{Severity: logging.Critical, Payload: err.Error()})
		return nil, err
	}
	bucket := stClient.Bucket(bucketName)

	dsClient, err := datastore.NewClient(ctx, projectID)
	if err != nil {
		err = fmt.Errorf("failed to create datastore client: %w", err)
		logger.Log(logging.Entry{Severity: logging.Critical, Payload: err.Error()})
		return nil, err
	}

	pubsubClient, err := pubsub.NewClient(ctx, projectID)
	if err != nil {
		err = fmt.Errorf("failed to create pubsub client: %w", err)
		logger.Log(logging.Entry{Severity: logging.Critical, Payload: err.Error()})
		return nil, err
	}
	topic := pubsubClient.Topic("failed-tasks")

	return &appEnv{
		logger: logger,
		bucket: bucket,
		ds:     dsClient,
		topic:  topic,
	}, nil
}

func main() {
	ctx := context.Background()
	env, err := setup(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup application: %v\n", err)
		os.Exit(1)
	}

	rcData, err := getRecordCheckerData(ctx, env.ds)
	if err != nil {
		env.logger.Log(logging.Entry{
			Severity: logging.Critical,
			Payload:  fmt.Sprintf("failed to get prior run data: %v", err)})
		os.Exit(1)
	}

	var wg sync.WaitGroup
	ch := make(chan checkRecordResult)

	var newInvalid []string
	var resultsWg sync.WaitGroup
	resultsWg.Add(1)
	go func() {
		defer resultsWg.Done()
		newInvalid = handleResults(ctx, env.logger, env.topic, ch)
	}()

	for _, id := range rcData.InvalidRecords {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			checkRecord(ctx, env.logger, env.ds, env.bucket, id, nil, ch)
		}(id)
	}
	runStartTime := time.Now().UTC()
	query := datastore.NewQuery("Vulnerability")
	if rcData.LastRun != nil {
		query = query.FilterField("modified", ">", *rcData.LastRun)
	}
	it := env.ds.Run(ctx, query)
	for {
		var vuln models.Vulnerability
		key, err := it.Next(&vuln)
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			env.logger.Log(logging.Entry{
				Severity: logging.Critical,
				Payload:  fmt.Sprintf("failed to query vulnerabilities: %v", err),
			})
			os.Exit(1)
		}
		wg.Add(1)
		go func(v models.Vulnerability, name string) {
			defer wg.Done()
			checkRecord(ctx, env.logger, env.ds, env.bucket, name, &v, ch)
		}(vuln, key.Name)
	}

	wg.Wait()
	close(ch)
	resultsWg.Wait()

	rcData = recordCheckerData{
		LastRun:        &runStartTime,
		InvalidRecords: newInvalid,
	}
	_, err = env.ds.Put(ctx, datastore.NameKey("JobData", "record_checker", nil), &rcData)
	if err != nil {
		env.logger.Log(logging.Entry{
			Severity: logging.Error,
			Payload:  fmt.Sprintf("failed to store run data: %v", err),
		})
	}
}

func handleResults(ctx context.Context, logger *logging.Logger, topic *pubsub.Topic, ch <-chan checkRecordResult) []string {
	var newInvalid []string
	for result := range ch {
		if result.Err != nil {
			logger.Log(logging.Entry{
				Severity: logging.Error,
				Payload:  result.Err,
			})
		}
		if result.NeedsRetry {
			newInvalid = append(newInvalid, result.ID)
			msg := pubsub.Message{
				Attributes: map[string]string{"type": "gcs_missing", "id": result.ID},
			}
			logger.Log(logging.Entry{
				Severity: logging.Info,
				Payload:  fmt.Sprintf("Publishing gcs_missing for %s", result.ID),
			})
			_, err := topic.Publish(ctx, &msg).Get(ctx)
			if err != nil {
				logger.Log(logging.Entry{
					Severity: logging.Error,
					Payload:  fmt.Sprintf("failed to publish message for %s: %v", result.ID, err),
				})
			}
		}
	}
	return newInvalid
}

func setupLogging(ctx context.Context, projectID string) (*logging.Logger, error) {
	client, err := logging.NewClient(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to create logging client: %w", err)
	}
	return client.Logger("record_checker"), nil
}

type recordCheckerData struct {
	LastRun        *time.Time `datastore:"last_run"`
	InvalidRecords []string   `datastore:"invalid_records"`
}

func getRecordCheckerData(ctx context.Context, cl *datastore.Client) (recordCheckerData, error) {
	infoKey := datastore.NameKey("JobData", "record_checker", nil)
	var data recordCheckerData
	err := cl.Get(ctx, infoKey, &data)
	if errors.Is(err, datastore.ErrNoSuchEntity) {
		err = nil
	}
	return data, err
}

type checkRecordResult struct {
	ID         string
	NeedsRetry bool
	Err        error
}

func checkRecord(ctx context.Context, logger *logging.Logger, cl *datastore.Client, bucket *storage.BucketHandle, id string, vuln *models.Vulnerability, out chan<- checkRecordResult) {
	res := checkRecordResult{ID: id}
	// Send the result when the function returns.
	defer func() { out <- res }()

	if vuln == nil {
		key := datastore.NameKey("Vulnerability", id, nil)
		var fetchedVuln models.Vulnerability
		if err := cl.Get(ctx, key, &fetchedVuln); err != nil {
			if errors.Is(err, datastore.ErrNoSuchEntity) {
				// This is a permanent error, don't retry.
				res.Err = fmt.Errorf("vulnerability %s not found in datastore: %w", id, err)
			} else {
				// This is likely a transient error, retry.
				res.NeedsRetry = true
				res.Err = fmt.Errorf("failed to get vulnerability %s from datastore: %w", id, err)
			}
			return
		}
		vuln = &fetchedVuln
	}

	obj := bucket.Object(fmt.Sprintf("all/pb/%s.pb", id))
	attrs, err := obj.Attrs(ctx)
	if err != nil {
		res.NeedsRetry = true
		if !errors.Is(err, storage.ErrObjectNotExist) {
			// Log the error if it's not the expected "not found" error.
			res.Err = fmt.Errorf("failed to get GCS attributes for %s: %w", id, err)
		}
		return
	}

	if attrs.CustomTime.Before(vuln.Modified) {
		res.NeedsRetry = true
	}
}
