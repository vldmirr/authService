package logger

import (
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// NewLogger initializes a new zerolog logger based on the environment.
// It supports "local", "dev", and "prod" environments with different logging levels.
func NewLogger(env string) zerolog.Logger {
	var logger zerolog.Logger

	switch env {
	case "local":
		logger = zerolog.New(os.Stdout).Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}).With().Timestamp().Logger().Level(zerolog.InfoLevel)
	case "dev":
		logger = zerolog.New(os.Stdout).Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}).With().Timestamp().Logger().Level(zerolog.DebugLevel)
	case "prod":
		logger = zerolog.New(os.Stdout).With().Timestamp().Logger().Level(zerolog.ErrorLevel)
	default:
		logger = zerolog.New(os.Stdout).With().Timestamp().Logger().Level(zerolog.InfoLevel)
	}

	return logger
}

// MiddlewareLogger returns a middleware that logs HTTP requests using zerolog.
// It logs method, path, remote address, request ID, response status, size, and duration.
func MiddlewareLogger(log zerolog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		log.Info().Msg("logger middleware initialized")

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logEntry := log.With().
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Str("remote_addr", r.RemoteAddr).
				Str("request_id", middleware.GetReqID(r.Context())).
				Logger()

			writer := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			timeStart := time.Now()

			defer func() {
				logEntry.Info().
					Int("status", writer.Status()).
					Int("size", writer.BytesWritten()).
					Dur("duration", time.Since(timeStart)).
					Msg("request completed")
			}()

			next.ServeHTTP(writer, r)
		})
	}
}

// Err returns a zerolog Event for logging errors.
// This allows for consistent error logging across the application.
func Err(err error) *zerolog.Event {
	if err == nil {
		return log.Error().Str("error", "unknown error")
	}
	return log.Error().Err(err)
}