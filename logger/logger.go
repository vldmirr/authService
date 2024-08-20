package logger

import (
	"github.com/go-chi/chi/v5/middleware"
	"github.com/phsym/console-slog"
	"log/slog"
	"net/http"
	"os"
	"time"
)

func NewLogger(env string) *slog.Logger {
	var logger *slog.Logger

	switch env {
	case "local":
		logger = slog.New(console.NewHandler(os.Stdout, &console.HandlerOptions{Level: slog.LevelInfo, AddSource: true}))
	case "dev":
		logger = slog.New(console.NewHandler(os.Stdout, &console.HandlerOptions{Level: slog.LevelDebug, AddSource: true}))
	case "prod":
		logger = slog.New(console.NewHandler(os.Stdout, &console.HandlerOptions{Level: slog.LevelError}))
	}

	return logger
}

func MiddlewareLogger(log *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		log = log.With(slog.String("component", "middleware/logger"))

		log.Info("logger middleware initialized")

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logEntry := log.With(
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("remote_addr", r.RemoteAddr),
				slog.String("request_id", middleware.GetReqID(r.Context())),
			)

			writer := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			timeStart := time.Now()

			defer func() {
				logEntry.Info("request completed",
					slog.Int("status", writer.Status()),
					slog.Int("size", writer.BytesWritten()),
					slog.Duration("duration", time.Since(timeStart)),
				)
			}()

			next.ServeHTTP(writer, r)
		})
	}
}

func Err(err error) slog.Attr {
	return slog.Attr{
		Key:   "error",
		Value: slog.StringValue(err.Error()),
	}
}
