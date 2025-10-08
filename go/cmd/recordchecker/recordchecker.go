// Package main runs the record checker, checking that each Vulnerability in Datastore has an up-to-date corresponding GCS object.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	"cloud.google.com/go/datastore"
	"cloud.google.com/go/pubsub/v2"
	"cloud.google.com/go/storage"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/models"
	"google.golang.org/api/iterator"
)

const (
	pubsubTopic = "failed-tasks"
	// defaultNumWorkers is the default number of concurrent workers to use.
	// This can be overridden by setting the NUM_WORKERS environment variable.
	defaultNumWorkers = 50

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
	if err != nil {
		if errors.Is(err, datastore.ErrNoSuchEntity) {
			logger.Info("no prior record checker last run time found")
		} else {
			return data, fmt.Errorf("failed to get %s: %w", JobDataLastRun, err)
		}
	} else {
		data.lastRun = lr.Value
	}

	invalidRecordsKey := datastore.NameKey(jobDataKind, JobDataInvalidRecords, nil)
	var ir jobDataInvalidRecordsEntity
	err = cl.Get(ctx, invalidRecordsKey, &ir)
	if err != nil {
		if errors.Is(err, datastore.ErrNoSuchEntity) {
			logger.Info("no prior record checker invalid records list found")
		} else {
			return data, fmt.Errorf("failed to get %s: %w", JobDataInvalidRecords, err)
		}
	} else {
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
			return fmt.Errorf("failed to write %s: %w", JobDataLastRun, err)
		}

		invalidRecordsKey := datastore.NameKey(jobDataKind, JobDataInvalidRecords, nil)
		ir := jobDataInvalidRecordsEntity{Value: data.invalidRecords}
		_, err = tx.Put(invalidRecordsKey, &ir)
		if err != nil {
			return fmt.Errorf("failed to write %s: %w", JobDataInvalidRecords, err)
		}

		return nil
	})

	return err
}

type checkTask struct {
	id   string
	vuln *models.Vulnerability
}

// run is the main application logic
func run(ctx context.Context, env *appEnv) error {
	rcData, err := getRecordCheckerData(ctx, env.ds)
	if err != nil {
		return fmt.Errorf("failed to get prior run data: %w", err)
	}

	tasksChan := make(chan checkTask)
	resultsChan := make(chan checkRecordResult)

	// Start the results handler
	var resultsWg sync.WaitGroup
	resultsWg.Add(1)
	var newInvalids []string
	go func() {
		defer resultsWg.Done()
		for result := range resultsChan {
			if handleResult(ctx, env.publisher, result) {
				newInvalids = append(newInvalids, result.id)
			}
		}
	}()

	// Start the worker pool
	var workerWg sync.WaitGroup
	for range env.numWorkers {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			for task := range tasksChan {
				resultsChan <- checkRecord(ctx, env.ds, env.bucket, task.id, task.vuln)
			}
		}()
	}

	// Queue all invalid records from the previous run.
	for _, id := range rcData.invalidRecords {
		logger.Debug("checking previously invalid record", slog.String("id", id))
		tasksChan <- checkTask{id: id}
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
		logger.Debug("checking newly modified record", slog.String("id", key.Name))
		tasksChan <- checkTask{id: key.Name, vuln: &vuln}
	}
	// Wait for all tasks to finish processing
	close(tasksChan)
	workerWg.Wait()
	close(resultsChan)
	resultsWg.Wait()

	// Update the record checker run data
	rcData = recordCheckerData{
		lastRun:        &runStartTime,
		invalidRecords: newInvalids,
	}
	if err := writeRecordCheckData(ctx, env.ds, rcData); err != nil {
		return fmt.Errorf("failed to store run data: %w", err)
	}

	return nil
}

// handleResult handles logging and sending pub/sub message to the recoverer.
// Returns true if a pub/sub message was sent to the recoverer,
// to indicate that we need to verify that the recoverer fixes the problem on the next run.
func handleResult(ctx context.Context, publisher *pubsub.Publisher, result checkRecordResult) bool {
	if result.err != nil {
		logger.Error("failed to process record", slog.String("id", result.id), slog.Any("err", result.err))
	}
	if result.needsRetry {
		msg := pubsub.Message{
			Attributes: map[string]string{"type": "gcs_missing", "id": result.id},
		}
		logger.Info("publishing gcs_missing message", slog.String("id", result.id))
		_, err := publisher.Publish(ctx, &msg).Get(ctx)
		if err != nil {
			logger.Error("failed publishing message", slog.String("id", result.id), slog.Any("err", err))
		}
	}

	return result.needsRetry
}

// appEnv holds the clients and other environment-specific resources.
type appEnv struct {
	bucket     *storage.BucketHandle
	ds         *datastore.Client
	publisher  *pubsub.Publisher
	numWorkers int
}

// setup initializes the application environment.
func setup(ctx context.Context) (*appEnv, error) {
	logger.InitGlobalLogger()
	projectID, ok := os.LookupEnv("GOOGLE_CLOUD_PROJECT")
	if !ok {
		return nil, errors.New("GOOGLE_CLOUD_PROJECT must be set")
	}

	bucketName, ok := os.LookupEnv("OSV_VULNERABILITIES_BUCKET")
	if !ok {
		err := errors.New("OSV_VULNERABILITIES_BUCKET must be set")
		return nil, err
	}
	stClient, err := storage.NewClient(ctx)
	if err != nil {
		err = fmt.Errorf("failed to create storage client: %w", err)
		return nil, err
	}
	bucket := stClient.Bucket(bucketName)

	dsClient, err := datastore.NewClient(ctx, projectID)
	if err != nil {
		err = fmt.Errorf("failed to create datastore client: %w", err)
		return nil, err
	}

	pubsubClient, err := pubsub.NewClient(ctx, projectID)
	if err != nil {
		err = fmt.Errorf("failed to create pubsub client: %w", err)
		return nil, err
	}
	publisher := pubsubClient.Publisher(pubsubTopic)

	numWorkers := defaultNumWorkers
	if numWorkersStr, ok := os.LookupEnv("NUM_WORKERS"); ok {
		if i, err := strconv.Atoi(numWorkersStr); err == nil {
			numWorkers = i
		} else {
			logger.Warn("invalid NUM_WORKERS value, using default", slog.String("value", numWorkersStr))
		}
	}

	return &appEnv{
		bucket:     bucket,
		ds:         dsClient,
		publisher:  publisher,
		numWorkers: numWorkers,
	}, nil
}

type checkRecordResult struct {
	id         string
	needsRetry bool
	err        error
}

func checkRecord(ctx context.Context, cl *datastore.Client, bucket *storage.BucketHandle, id string, vuln *models.Vulnerability) checkRecordResult {
	res := checkRecordResult{id: id}

	if vuln == nil {
		key := datastore.NameKey("Vulnerability", id, nil)
		var fetchedVuln models.Vulnerability
		if err := cl.Get(ctx, key, &fetchedVuln); err != nil {
			if errors.Is(err, datastore.ErrNoSuchEntity) {
				// This is a permanent error, don't retry.
				res.err = fmt.Errorf("vulnerability %s not found in datastore: %w", id, err)
			} else {
				// This is likely a transient error, retry.
				res.needsRetry = true
				res.err = fmt.Errorf("failed to get vulnerability %s from datastore: %w", id, err)
			}

			return res
		}
		vuln = &fetchedVuln
	}

	obj := bucket.Object(fmt.Sprintf("all/pb/%s.pb", id))
	attrs, err := obj.Attrs(ctx)
	if err != nil {
		res.needsRetry = true
		if !errors.Is(err, storage.ErrObjectNotExist) {
			// Log the error if it's not the expected "not found" error.
			res.err = fmt.Errorf("failed to get GCS attributes for %s: %w", id, err)
		}

		return res
	}

	if attrs.CustomTime.Before(vuln.Modified) {
		res.needsRetry = true
	}

	return res
}

func main() {
	ctx := context.Background()
	env, err := setup(ctx)
	if err != nil {
		logger.Fatal("failed setting up environment", slog.Any("err", err))
	}
	logger.Info("starting record checker")
	if err := run(ctx, env); err != nil {
		logger.Fatal("failed running record checker", slog.Any("err", err))
	}
	logger.Info("record checker done")
}
