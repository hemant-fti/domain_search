package logger

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"runtime"
	"sync"
	"time"
)

type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(err error, msg string, args ...any)
	Close() error
}

type Config struct {
	Level      slog.Level
	FilePath   string
	Console    bool
	JSONFormat bool
	AddSource  bool
	Output     io.Writer
}

type logger struct {
	log       *slog.Logger
	file      *os.File
	closeOnce sync.Once
	closeErr  error
}

var (
	globalLogger *logger
	globalMu     sync.RWMutex
)

func New() (Logger, error) {
	return NewWithConfig(Config{
		Level:      slog.LevelInfo,
		JSONFormat: true,
		Console:    true,
		AddSource:  false,
	})
}

func NewWithConfig(cfg Config) (Logger, error) {
	var writers []io.Writer

	if cfg.Output != nil {
		writers = append(writers, cfg.Output)
	} else if cfg.Console {
		writers = append(writers, os.Stderr)
	}

	var file *os.File

	if cfg.FilePath != "" {
		var err error

		file, err = OpenLogFile(cfg.FilePath)
		if err != nil {
			return nil, err
		}

		writers = append(writers, file)
	}

	if len(writers) == 0 {
		return nil, errors.New("logger requires at least one output")
	}

	opts := &slog.HandlerOptions{
		Level:     cfg.Level,
		AddSource: false,
	}

	output := io.MultiWriter(writers...)

	var handler slog.Handler

	if cfg.JSONFormat {
		handler = slog.NewJSONHandler(output, opts)
	} else {
		handler = slog.NewTextHandler(output, opts)
	}

	return &logger{
		log:  slog.New(handler),
		file: file,
	}, nil
}

// Debug logs a debug message.
func (l *logger) Debug(msg string, args ...any) {
	l.logAt(slog.LevelDebug, msg, args...)
}

// Info logs an informational message.
func (l *logger) Info(msg string, args ...any) {
	l.logAt(slog.LevelInfo, msg, args...)
}

// Warn logs a warning message.
func (l *logger) Warn(msg string, args ...any) {
	l.logAt(slog.LevelWarn, msg, args...)
}

// Error logs an error message.
func (l *logger) Error(err error, msg string, args ...any) {
	if err != nil {
		args = append(args, "error", err)
	}

	l.logAt(slog.LevelError, msg, args...)
}

// Close closes the logger's file.
func (l *logger) Close() error {
	l.closeOnce.Do(func() {
		if l.file != nil {
			l.closeErr = l.file.Close()
		}
	})

	return l.closeErr
}

// Init initializes the global logger.
func Init(cfg Config) error {
	newLogger, err := NewWithConfig(cfg)
	if err != nil {
		return err
	}

	globalMu.Lock()
	defer globalMu.Unlock()

	if globalLogger != nil {
		_ = newLogger.Close()
		return errors.New("global logger already initialized")
	}

	globalLogger = newLogger.(*logger)

	return nil
}

// getLogger returns the initialized global logger.
func getLogger() *logger {
	globalMu.RLock()
	l := globalLogger
	globalMu.RUnlock()

	if l != nil {
		return l
	}

	globalMu.Lock()
	defer globalMu.Unlock()

	if globalLogger == nil {
		newLogger, err := NewWithConfig(Config{
			Level:      slog.LevelInfo,
			JSONFormat: true,
			Console:    true,
			AddSource:  false,
		})
		if err != nil {
			panic(err)
		}

		globalLogger = newLogger.(*logger)
	}

	return globalLogger
}

// Global logging functions.

func Debug(msg string, args ...any) {
	getLogger().logAt(slog.LevelDebug, msg, args...)
}

func Info(msg string, args ...any) {
	getLogger().logAt(slog.LevelInfo, msg, args...)
}

func Warn(msg string, args ...any) {
	getLogger().logAt(slog.LevelWarn, msg, args...)
}

func Error(err error, msg string, args ...any) {
	l := getLogger()

	if err != nil {
		args = append(args, "error", err)
	}

	l.logAt(slog.LevelError, msg, args...)
}

// CloseGlobal closes the global logger.
func CloseGlobal() error {
	globalMu.Lock()
	defer globalMu.Unlock()

	if globalLogger == nil {
		return nil
	}

	err := globalLogger.Close()
	globalLogger = nil

	return err
}

// logAt creates and writes a log record.
//
// runtime.Callers(3) skips:
// 0: runtime.Callers
// 1: logAt
// 2: the caller's logging function
//
// The resulting PC points to the application call site.
func (l *logger) logAt(
	level slog.Level,
	msg string,
	args ...any,
) {
	ctx := context.Background()
	handler := l.log.Handler()

	if !handler.Enabled(ctx, level) {
		return
	}

	var pcs [1]uintptr

	runtime.Callers(3, pcs[:])

	record := slog.NewRecord(
		time.Now(),
		level,
		msg,
		pcs[0],
	)

	record.Add(args...)

	_ = handler.Handle(ctx, record)
}
