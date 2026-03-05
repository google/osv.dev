package logger

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	texporter "github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/trace"
	"go.opentelemetry.io/contrib/detectors/gcp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

var (
	slogLogger = slog.New(&contextHandler{newLocalHandler(os.Stdout)})
	once       sync.Once
	tp         *sdktrace.TracerProvider
	projectID  string
)

// InitGlobalLogger initializes the global slog logger and GCP observability clients.
// Users should call Close() before the program exits.
func InitGlobalLogger() {
	once.Do(func() {
		inGKE := os.Getenv("KUBERNETES_SERVICE_HOST") != ""
		inCloudRun := os.Getenv("K_SERVICE") != ""
		inCloud := inGKE || inCloudRun
		if !inCloud {
			// The local handler is initialized by default.
			return
		}

		projectID = os.Getenv("GOOGLE_CLOUD_PROJECT")
		if projectID != "" {
			serviceName := os.Getenv("K_SERVICE")
			if serviceName == "" {
				// Fallback to binary name for GKE services where K_SERVICE is not set.
				serviceName = filepath.Base(os.Args[0])
			}

			initTracing(context.Background(), projectID, serviceName)
		}
		handler := slog.NewJSONHandler(os.Stdout, cloudHandlerOptions())
		slogLogger = slog.New(&contextHandler{handler})
	})
}

// Close flushes any buffered log or trace reports.
func Close() {
	if tp != nil {
		if err := tp.Shutdown(context.Background()); err != nil {
			fmt.Fprintf(os.Stderr, "Error shutting down tracer provider: %v", err)
		}
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

	// If TRACE_SAMPLE_RATE is unset, default to 5% to prevent unintentional cost and performance impact on high-traffic services.
	sampleRate := 0.05
	if r := os.Getenv("TRACE_SAMPLE_RATE"); r != "" {
		if parsed, err := strconv.ParseFloat(r, 64); err == nil {
			sampleRate = parsed
		}
	}

	tp = sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(toggleSampler{
			delegate: sdktrace.TraceIDRatioBased(sampleRate),
		})),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
	))
}

// toggleSampler allows overriding the sampling rate via span attributes.
// Use trace.WithAttributes(attribute.Float64("override_sample_rate", 1.0)) to force sampling.
type toggleSampler struct {
	delegate sdktrace.Sampler
}

func (s toggleSampler) ShouldSample(p sdktrace.SamplingParameters) sdktrace.SamplingResult {
	for _, attr := range p.Attributes {
		if attr.Key == "override_sample_rate" {
			return sdktrace.TraceIDRatioBased(attr.Value.AsFloat64()).ShouldSample(p)
		}
	}

	return s.delegate.ShouldSample(p)
}

func (s toggleSampler) Description() string {
	return "toggleSampler"
}

func cloudHandlerOptions() *slog.HandlerOptions {
	level := slog.LevelInfo
	if lvl := os.Getenv("LOG_LEVEL"); lvl != "" {
		switch strings.ToLower(lvl) {
		case "debug":
			level = slog.LevelDebug
		case "info":
			level = slog.LevelInfo
		case "warn":
			level = slog.LevelWarn
		case "error":
			level = slog.LevelError
		}
	}

	return &slog.HandlerOptions{
		AddSource: true,
		Level:     level,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			// Remap "level" to "severity"
			if a.Key == slog.LevelKey {
				if level, ok := a.Value.Any().(slog.Level); ok {
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
			}
			// Remap "msg" to "message"
			if a.Key == slog.MessageKey {
				return slog.Attr{Key: "message", Value: a.Value}
			}
			// Remap "source" to "sourceLocation"
			if a.Key == slog.SourceKey {
				if source, ok := a.Value.Any().(*slog.Source); ok {
					source.File = filepath.Base(source.File)

					return slog.Attr{Key: "logging.googleapis.com/sourceLocation", Value: slog.AnyValue(source)}
				}
			}

			if a.Key == "err" || a.Key == "error" {
				if err, ok := a.Value.Any().(error); ok {
					// Attach the error as an exception (which error reporting looks for) to the log record.
					return slog.Any("exception", err)
				}
			}

			return a
		},
	}
}
