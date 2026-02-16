package logger

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"cloud.google.com/go/errorreporting"
	texporter "github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/trace"
	"go.opentelemetry.io/contrib/detectors/gcp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

var (
	slogLogger  *slog.Logger
	errorClient *errorreporting.Client
	once        sync.Once
	tp          *sdktrace.TracerProvider
	projectID   string
)

// InitGlobalLogger initializes the global slog logger and GCP observability clients.
func InitGlobalLogger(ctx context.Context) {
	once.Do(func() {
		if slogLogger != nil {
			return
		}

		inGKE := os.Getenv("KUBERNETES_SERVICE_HOST") != ""
		inCloudRun := os.Getenv("K_SERVICE") != ""
		inCloud := inGKE || inCloudRun

		var handler slog.Handler
		if inCloud {
			projectID = os.Getenv("GOOGLE_CLOUD_PROJECT")
			if projectID != "" {
				serviceName := os.Getenv("K_SERVICE")
				if serviceName == "" {
					// Fallback to binary name for GKE services where K_SERVICE is not set.
					serviceName = filepath.Base(os.Args[0])
				}

				initErrorReporting(ctx, projectID, serviceName)
				initTracing(ctx, projectID, serviceName)
			}
			handler = slog.NewJSONHandler(os.Stdout, cloudHandlerOptions())
		} else {
			handler = newLocalHandler(os.Stdout)
		}
		slogLogger = slog.New(handler)
	})
}

// Close flushes any buffered log, trace or error reports.
func Close() {
	if errorClient != nil {
		errorClient.Close()
	}
	if tp != nil {
		if err := tp.Shutdown(context.Background()); err != nil {
			fmt.Fprintf(os.Stderr, "Error shutting down tracer provider: %v", err)
		}
	}
}

func initErrorReporting(ctx context.Context, projectID, serviceName string) {
	var err error
	errorClient, err = errorreporting.NewClient(ctx, projectID, errorreporting.Config{
		ServiceName: serviceName,
		OnError: func(err error) {
			fmt.Fprintf(os.Stderr, "Could not log error to Error Reporting: %v\n", err)
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create errorreporting client: %v\n", err)
	}
}

func initTracing(ctx context.Context, projectID, serviceName string) {
	exporter, err := texporter.New(texporter.WithProjectID(projectID))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create Cloud Trace exporter: %v\n", err)
		return
	}

	res, err := resource.New(ctx,
		resource.WithDetectors(gcp.NewDetector()),
		resource.WithTelemetrySDK(),
		resource.WithAttributes(semconv.ServiceNameKey.String(serviceName)),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to detect resource attributes: %v\n", err)
		res = resource.NewWithAttributes(semconv.SchemaURL, semconv.ServiceNameKey.String(serviceName))
	}

	tp = sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(0.05))),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
	))
}

func cloudHandlerOptions() *slog.HandlerOptions {
	return &slog.HandlerOptions{
		AddSource: true,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			// Remap "level" to "severity"
			if a.Key == slog.LevelKey {
				level := a.Value.Any().(slog.Level)
				var levelStr string
				switch level {
				case slog.LevelDebug:
					levelStr = "DEBUG"
				case slog.LevelInfo:
					levelStr = "INFO"
				case slog.LevelWarn:
					levelStr = "WARNING"
				case slog.LevelError:
					levelStr = "ERROR"
				default:
					levelStr = "DEFAULT"
				}

				return slog.String("severity", levelStr)
			}
			// Remap "msg" to "message"
			if a.Key == slog.MessageKey {
				return slog.Attr{Key: "message", Value: a.Value}
			}
			// Remap "source" to "sourceLocation"
			if a.Key == slog.SourceKey {
				source := a.Value.Any().(*slog.Source)
				source.File = filepath.Base(source.File)

				return slog.Attr{Key: "sourceLocation", Value: slog.AnyValue(source)}
			}

			return a
		},
	}
}
