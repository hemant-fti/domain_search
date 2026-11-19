package main

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

	"github.com/spf13/cobra"
)

const logDirectory = "logs"

var (
	commandResultsFile = filepath.Join(logDirectory, "command-results.jsonl")
	commandErrorsFile  = filepath.Join(logDirectory, "command-errors.jsonl")

	commandLogMu sync.Mutex

	sensitiveFlag     = regexp.MustCompile(`(?i)(password|passwd|token|secret|api[-_]?key|authorization|credential|private[-_]?key)`)
	sensitiveText     = regexp.MustCompile(`(?i)(password|passwd|token|secret|api[-_]?key|authorization|credential)\s*[:=]\s*("[^"]*"|'[^']*'|[^\s,;]+)`)
	privateKeyPattern = regexp.MustCompile(
		`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`,
	)
)

func ensureLogDirectory() error {
	if err := os.MkdirAll(logDirectory, 0755); err != nil {
		return fmt.Errorf("create logs directory: %w", err)
	}

	return nil
}

type commandOutputCaptureKey struct{}

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
	Command    string    `json:"command"`
	Args       []string  `json:"args,omitempty"`
	Status     string    `json:"status"`
	ExecutedAt time.Time `json:"executed_at"`
	DurationMS int64     `json:"duration_ms"`
	Error      struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func captureCommandFileOutput(ctx context.Context, data []byte) {
	buffer, ok := ctx.Value(commandOutputCaptureKey{}).(*bytes.Buffer)
	if !ok {
		return
	}

	buffer.Write(data)
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
	if err := ensureLogDirectory(); err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}

	data = append(data, '\n')

	commandLogMu.Lock()
	defer commandLogMu.Unlock()

	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(data)
	return err
}

func recordCommandExecution(
	cmd *cobra.Command,
	args []string,
	startedAt time.Time,
	stdout string,
	fileOutput string,
	executionErr error,
) {
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
			// Logging must not change the command's exit status.
			// Report the logging failure separately.
			_, _ = os.Stderr.WriteString("Warning: could not write command error history: " + err.Error() + "\n")
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
		_, _ = os.Stderr.WriteString("Warning: could not write command result history: " + err.Error() + "\n")
	}
}
