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

const (
	pubsubTopic = "failed-tasks"
	numWorkers  = 50

	jobDataKind           = "JobData"
	JobDataLastRun        = "record_checker_last_run"
	JobDataInvalidRecords = "record_checker_invalid_records"
)

type jobDataLastRunEntity struct {
	Value *time.Time `datastore:"value,noindex"`
}
type jobDataInvalidRecordsEntity struct {
	Value []string `datastore:"value,noindex"`
}

type recordCheckerData struct {
	lastRun        *time.Time
	invalidRecords []string
}

func getRecordCheckerData(ctx context.Context, cl *datastore.Client) (recordCheckerData, error) {
	var data recordCheckerData

	lastRunKey := datastore.NameKey(jobDataKind, JobDataLastRun, nil)
	var lr jobDataLastRunEntity
	err := cl.Get(ctx, lastRunKey, &lr)
	if err != nil && !errors.Is(err, datastore.ErrNoSuchEntity) {
		return data, err
	}
	if err == nil {
		data.lastRun = lr.Value
	}

	invalidRecordsKey := datastore.NameKey(jobDataKind, JobDataInvalidRecords, nil)
	var ir jobDataInvalidRecordsEntity
	err = cl.Get(ctx, invalidRecordsKey, &ir)
	if err != nil && !errors.Is(err, datastore.ErrNoSuchEntity) {
		return data, err
	}
	if err == nil {
		data.invalidRecords = ir.Value
	}

	return data, nil
}

func writeRecordCheckData(ctx context.Context, cl *datastore.Client, data recordCheckerData) error {
	_, err := cl.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		lastRunKey := datastore.NameKey(jobDataKind, JobDataLastRun, nil)
		lr := jobDataLastRunEntity{Value: data.lastRun}
		_, err := tx.Put(lastRunKey, &lr)
		if err != nil {
			return err
		}

		invalidRecordsKey := datastore.NameKey(jobDataKind, JobDataInvalidRecords, nil)
		ir := jobDataInvalidRecordsEntity{Value: data.invalidRecords}
		_, err = tx.Put(invalidRecordsKey, &ir)
		if err != nil {
			return err
		}

		return nil
	})

	return err
}

// run is the main application logic
func run(ctx context.Context, env *appEnv) error {
	rcData, err := getRecordCheckerData(ctx, env.ds)
	if err != nil {
		return fmt.Errorf("failed to get prior run data: %w", err)
	}

	tasksChan := make(chan struct {
		ID   string
		Vuln *models.Vulnerability
	})
	resultsChan := make(chan checkRecordResult)

	// Start the results handler
	var resultsWg sync.WaitGroup
	resultsWg.Add(1)
	var newInvalid []string
	go func() {
		defer resultsWg.Done()
		for result := range resultsChan {
			if handleResult(ctx, env.logger, env.topic, result) {
				newInvalid = append(newInvalid, result.ID)
			}
		}
	}()

	// Start the worker pool
	var workerWg sync.WaitGroup
	for range numWorkers {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			for task := range tasksChan {
				checkRecord(ctx, env.logger, env.ds, env.bucket, task.ID, task.Vuln, resultsChan)
			}
		}()
	}

	// Queue all invalid records from the previous run.
	for _, id := range rcData.invalidRecords {
		tasksChan <- struct {
			ID   string
			Vuln *models.Vulnerability
		}{ID: id}
	}

	// Queue all new records.
	runStartTime := time.Now().UTC()
	query := datastore.NewQuery("Vulnerability")
	if rcData.lastRun != nil {
		query = query.FilterField("modified", ">", *rcData.lastRun)
	}
	it := env.ds.Run(ctx, query)
	for {
		var vuln models.Vulnerability
		key, err := it.Next(&vuln)
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to query vulnerabilities: %w", err)
		}
		tasksChan <- struct {
			ID   string
			Vuln *models.Vulnerability
		}{ID: key.Name, Vuln: &vuln}
	}
	// Wait for all tasks to finish processing
	close(tasksChan)
	workerWg.Wait()
	close(resultsChan)
	resultsWg.Wait()

	// Update the record checker run data
	rcData = recordCheckerData{
		lastRun:        &runStartTime,
		invalidRecords: newInvalid,
	}
	if err := writeRecordCheckData(ctx, env.ds, rcData); err != nil {
		return fmt.Errorf("failed to store run data: %w", err)
	}

	return nil
}

func handleResult(ctx context.Context, logger *logging.Logger, topic *pubsub.Topic, result checkRecordResult) bool {
	wasInvalid := false
	if result.Err != nil {
		logger.Log(logging.Entry{
			Severity: logging.Error,
			Payload:  fmt.Sprintf("failed to process record %s: %v", result.ID, result.Err),
		})
	}
	if result.NeedsRetry {
		wasInvalid = true
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
	return wasInvalid
}

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
	topic := pubsubClient.Topic(pubsubTopic)

	return &appEnv{
		logger: logger,
		bucket: bucket,
		ds:     dsClient,
		topic:  topic,
	}, nil
}

func setupLogging(ctx context.Context, projectID string) (*logging.Logger, error) {
	client, err := logging.NewClient(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to create logging client: %w", err)
	}
	return client.Logger("record_checker"), nil
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

func main() {
	ctx := context.Background()
	env, err := setup(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup application: %v\n", err)
		os.Exit(1)
	}
	if err := run(ctx, env); err != nil {
		fmt.Fprintf(os.Stderr, "failed to run application: %v\n", err)
		os.Exit(1)
	}
}
