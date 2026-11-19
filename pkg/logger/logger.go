package logger

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(err error, msg string, args ...any)
}

type logger struct {
	log *slog.Logger
}

type Config struct {
	Level      string
	JSONFormat bool
	Output     io.Writer
}

var (
	globalLogger Logger
	once         sync.Once
)

func (l *logger) Debug(msg string, args ...any) {
	l.log.Debug(msg, args...)
}

func (l *logger) Info(msg string, args ...any) {
	l.log.Info(msg, args...)
}

func (l *logger) Warn(msg string, args ...any) {
	l.log.Warn(msg, args...)
}

func (l *logger) Error(err error, msg string, args ...any) {
	if err != nil {
		args = append(args, "error", err)
	}

	l.log.Error(msg, args...)
}

func New() Logger {
	return NewWithConfig(Config{
		Level:      "info",
		JSONFormat: true,
		Output:     os.Stdout,
	})
}

func NewWithConfig(cfg Config) Logger {
	output := cfg.Output
	if output == nil {
		output = os.Stdout
	}

	var level slog.Level

	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler

	if cfg.JSONFormat {
		handler = slog.NewJSONHandler(output, opts)
	} else {
		handler = slog.NewTextHandler(output, opts)
	}

	return &logger{
		log: slog.New(handler),
	}
}

// Init initializes the global logger once.
func Init(cfg Config) {
	once.Do(func() {
		globalLogger = NewWithConfig(cfg)
	})
}

// getLogger returns the initialized global logger.
func getLogger() Logger {
	if globalLogger == nil {
		Init(Config{
			Level:      "info",
			JSONFormat: true,
			Output:     os.Stdout,
		})
	}

	return globalLogger
}

// Global logging functions.

func Debug(msg string, args ...any) {
	getLogger().Debug(msg, args...)
}

func Info(msg string, args ...any) {
	getLogger().Info(msg, args...)
}

func Warn(msg string, args ...any) {
	getLogger().Warn(msg, args...)
}

func Error(err error, msg string, args ...any) {
	getLogger().Error(err, msg, args...)
}
