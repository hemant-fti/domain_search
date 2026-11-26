package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// Logger is the application logging contract.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(err error, msg string, args ...any)
	// With returns a child logger with the given attributes attached.
	// Closing a child is a no-op; close the root logger.
	With(args ...any) Logger
	Close() error
}

type Config struct {
	Level      slog.Level
	FilePath   string
	Console    bool // write to stderr
	JSONFormat bool
	AddSource  bool
	Output     io.Writer // additional sink (e.g. a rotating writer); additive with Console/FilePath
}

// resource owns closable state; only the root logger holds one.
type resource struct {
	file *os.File
	once sync.Once
	err  error
}

func (r *resource) close() error {
	r.once.Do(func() {
		if r.file != nil {
			r.err = r.file.Close()
		}
	})
	return r.err
}

type logger struct {
	log   *slog.Logger
	owner *resource // nil for child loggers
}

// tolerantWriter writes to every sink even if one fails.
type tolerantWriter struct{ sinks []io.Writer }

func (t tolerantWriter) Write(p []byte) (int, error) {
	var errs []error
	for _, w := range t.sinks {
		if _, err := w.Write(p); err != nil {
			errs = append(errs, err)
		}
	}
	return len(p), errors.Join(errs...)
}

func build(cfg Config) (*logger, error) {
	var sinks []io.Writer

	if cfg.Console {
		sinks = append(sinks, os.Stderr)
	}
	if cfg.Output != nil {
		sinks = append(sinks, cfg.Output)
	}

	res := &resource{}
	if cfg.FilePath != "" {
		f, err := OpenLogFile(cfg.FilePath)
		if err != nil {
			return nil, err
		}
		res.file = f
		sinks = append(sinks, f)
	}

	if len(sinks) == 0 {
		return nil, errors.New("logger requires at least one output")
	}

	opts := &slog.HandlerOptions{
		Level:     cfg.Level,
		AddSource: cfg.AddSource,
	}

	out := tolerantWriter{sinks: sinks}

	var h slog.Handler
	if cfg.JSONFormat {
		h = slog.NewJSONHandler(out, opts)
	} else {
		h = slog.NewTextHandler(out, opts)
	}

	return &logger{log: slog.New(h), owner: res}, nil
}

// NewWithConfig builds an independent logger. Callers must Close it.
func NewWithConfig(cfg Config) (Logger, error) {
	l, err := build(cfg)
	if err != nil {
		return nil, err // avoid typed-nil interface
	}
	return l, nil
}

func (l *logger) Debug(msg string, args ...any) { l.logAt(slog.LevelDebug, msg, args...) }
func (l *logger) Info(msg string, args ...any)  { l.logAt(slog.LevelInfo, msg, args...) }
func (l *logger) Warn(msg string, args ...any)  { l.logAt(slog.LevelWarn, msg, args...) }

func (l *logger) Error(err error, msg string, args ...any) {
	if err != nil {
		// Clip forces a copy so we never write into the caller's backing array.
		args = append(slices.Clip(args), slog.Any("error", err))
	}
	l.logAt(slog.LevelError, msg, args...)
}

func (l *logger) With(args ...any) Logger {
	return &logger{log: l.log.With(args...)}
}

func (l *logger) Close() error {
	if l.owner == nil {
		return nil
	}
	return l.owner.close()
}

// logAt writes a record with the correct call-site PC.
//
// runtime.Callers(3) skips Callers, logAt, and the exported logging
// function (method or package-level), landing on the application call site.
func (l *logger) logAt(level slog.Level, msg string, args ...any) {
	ctx := context.Background()
	h := l.log.Handler()
	if !h.Enabled(ctx, level) {
		return
	}

	var pcs [1]uintptr
	runtime.Callers(3, pcs[:])

	r := slog.NewRecord(time.Now(), level, msg, pcs[0])
	r.Add(args...)

	_ = h.Handle(ctx, r) // logging must never fail the caller
}

// ---- Global logger ----

var global atomic.Pointer[logger]

// Init configures the global logger, replacing (and closing) any previous one.
// Call once at startup and `defer logger.Close()` in main.
func Init(cfg Config) error {
	l, err := build(cfg)
	if err != nil {
		return err
	}
	if old := global.Swap(l); old != nil {
		_ = old.Close()
	}
	return nil
}

// Close shuts down the global logger.
func Close() error {
	if l := global.Swap(nil); l != nil {
		return l.Close()
	}
	return nil
}

func get() *logger {
	if l := global.Load(); l != nil {
		return l
	}
	// Safe default: JSON to stderr. Cannot fail, so no panic path.
	def := &logger{
		log:   slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})),
		owner: &resource{},
	}
	if global.CompareAndSwap(nil, def) {
		return def
	}
	return global.Load()
}

func Debug(msg string, args ...any) { get().logAt(slog.LevelDebug, msg, args...) }
func Info(msg string, args ...any)  { get().logAt(slog.LevelInfo, msg, args...) }
func Warn(msg string, args ...any)  { get().logAt(slog.LevelWarn, msg, args...) }

func Error(err error, msg string, args ...any) {
	if err != nil {
		args = append(slices.Clip(args), slog.Any("error", err))
	}
	get().logAt(slog.LevelError, msg, args...)
}

func With(args ...any) Logger { return get().With(args...) }

// OpenLogFile creates parent dirs and opens the file for append.
func OpenLogFile(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
}

func MarshalJSON(result any, pretty bool) ([]byte, error) {
	var buffer bytes.Buffer

	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)

	if pretty {
		encoder.SetIndent("", "  ")
	}

	if err := encoder.Encode(result); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}
