package history

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"domain-search/internal/logger"

	"github.com/spf13/cobra"
)

const LogDirectory = "logs"

var (
	commandResultsFile = filepath.Join(LogDirectory, "command-results.jsonl")
	commandErrorsFile  = filepath.Join(LogDirectory, "command-errors.jsonl")

	commandLogMu sync.Mutex

	loggerMu sync.RWMutex
	log      logger.Logger

	sensitiveFlag = regexp.MustCompile(`(?i)(password|passwd|token|secret|api[-_]?key|authorization|credential|private[-_]?key)`)
	sensitiveText = regexp.MustCompile(`(?i)(password|passwd|token|secret|api[-_]?key|authorization|credential)\s*[:=]\s*("[^"]*"|'[^']*'|[^\s,;]+)`)

	privateKeyPattern = regexp.MustCompile(
		`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`,
	)
)

func SetLogger(l logger.Logger) {
	if l == nil {
		return
	}

	loggerMu.Lock()
	defer loggerMu.Unlock()

	log = l
}

func logError(err error, msg string, args ...any) {
	loggerMu.RLock()
	l := log
	loggerMu.RUnlock()

	if l != nil {
		l.Error(err, msg, args...)
	}
}

func EnsureLogDirectory() error {
	if err := os.MkdirAll(LogDirectory, 0755); err != nil {
		return fmt.Errorf("create logs directory: %w", err)
	}

	return nil
}

type CommandOutputCaptureKey struct{}

type commandHistoryRecord struct {
	Command    string    `json:"command"`
	Args       []string  `json:"args,omitempty"`
	Status     string    `json:"status"`
	ExecutedAt time.Time `json:"executed_at"`
	DurationMS int64     `json:"duration_ms"`
	Output     string    `json:"output,omitempty"`
	OutputFile string    `json:"output_file,omitempty"`
}

type commandErrorRecord struct {
	Command    string    `json:"command,omitempty"`
	Args       []string  `json:"args,omitempty"`
	Status     string    `json:"status,omitempty"`
	ExecutedAt time.Time `json:"executed_at,omitempty"`
	DurationMS int64     `json:"duration_ms,omitempty"`

	Type      string `json:"type,omitempty"`
	Code      string `json:"code,omitempty"`
	Message   string `json:"message,omitempty"`
	Details   string `json:"details,omitempty"`
	Component string `json:"component,omitempty"`

	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func CaptureCommandFileOutput(ctx context.Context, data []byte) {
	if ctx == nil {
		return
	}

	buffer, ok := ctx.Value(CommandOutputCaptureKey{}).(*bytes.Buffer)
	if !ok {
		return
	}

	_, _ = buffer.Write(data)
}

func sanitizeCommandArgs(args []string) []string {
	result := make([]string, len(args))
	redactNext := false

	for i, arg := range args {
		if redactNext {
			result[i] = "[REDACTED]"
			redactNext = false
			continue
		}

		if strings.HasPrefix(arg, "--") {
			parts := strings.SplitN(strings.TrimPrefix(arg, "--"), "=", 2)

			if sensitiveFlag.MatchString(parts[0]) {
				if len(parts) == 2 {
					result[i] = "--" + parts[0] + "=[REDACTED]"
				} else {
					result[i] = arg
					redactNext = true
				}
				continue
			}
		}

		result[i] = arg
	}

	return result
}

func sanitizeCommandOutput(value string) string {
	value = privateKeyPattern.ReplaceAllString(value, "[REDACTED PRIVATE KEY]")
	return sensitiveText.ReplaceAllString(value, "$1=[REDACTED]")
}

func appendCommandJSON(path string, record any) error {
	if err := EnsureLogDirectory(); err != nil {
		return err
	}

	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal command record to JSON: %w", err)
	}

	data = append(data, '\n')

	commandLogMu.Lock()
	defer commandLogMu.Unlock()

	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open command history file: %w", err)
	}
	defer file.Close()

	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write command history: %w", err)
	}

	return nil
}

func RecordCommandExecution(cmd *cobra.Command, args []string, startedAt time.Time, stdout string, fileOutput string, executionErr error) {
	commandName := "hostscope"

	if cmd != nil {
		commandName = cmd.CommandPath()
	}

	if stdout == "" {
		stdout = fileOutput
	}

	output := sanitizeCommandOutput(stdout)

	duration := time.Since(startedAt).Milliseconds()
	executedAt := startedAt.UTC()

	if executionErr != nil {
		record := commandErrorRecord{
			Command:    commandName,
			Args:       sanitizeCommandArgs(args),
			Status:     "failed",
			ExecutedAt: executedAt,
			DurationMS: duration,
		}

		record.Error.Code = "COMMAND_FAILED"
		record.Error.Message = sanitizeCommandOutput(executionErr.Error())

		if output != "" {
			record.Error.Message += "\nOutput: " + output
		}

		if err := appendCommandJSON(commandErrorsFile, record); err != nil {
			logError(
				err,
				"Could not write command error history",
				"file", commandErrorsFile,
				"command", commandName,
			)
		}

		return
	}

	outputFile := ""

	if cmd != nil {
		outputFile, _ = cmd.Flags().GetString("output")
	}

	record := commandHistoryRecord{
		Command:    commandName,
		Args:       sanitizeCommandArgs(args),
		Status:     "completed",
		ExecutedAt: executedAt,
		DurationMS: duration,
		Output:     output,
		OutputFile: outputFile,
	}

	if err := appendCommandJSON(commandResultsFile, record); err != nil {
		logError(
			err,
			"Could not write command result history",
			"file", commandResultsFile,
			"command", commandName,
		)
	}
}

func RecordScanError(code string, message string, component string, err error) error {
	details := ""

	if err != nil {
		details = sanitizeCommandOutput(err.Error())
	}

	record := commandErrorRecord{
		Type:       "warning",
		Code:       code,
		Message:    sanitizeCommandOutput(message),
		Details:    details,
		Component:  component,
		ExecutedAt: time.Now().UTC(),
	}

	if writeErr := appendCommandJSON(commandErrorsFile, record); writeErr != nil {
		logError(
			writeErr,
			"Could not write scan error history",
			"file", commandErrorsFile,
			"component", component,
			"code", code,
		)

		return writeErr
	}

	return nil
}
