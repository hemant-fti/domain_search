package history

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"domain-search/internal/logger"
	"domain-search/internal/security"

	"github.com/spf13/cobra"
)

const LogDirectory = "logs"

var (
	commandResultsFile = filepath.Join(
		LogDirectory,
		"command-results.jsonl",
	)

	commandErrorsFile = filepath.Join(
		LogDirectory,
		"command-errors.jsonl",
	)

	ScanResultsFile = filepath.Join(
		LogDirectory,
		"scan-results.jsonl",
	)

	ScanErrorsFile = filepath.Join(
		LogDirectory,
		"scan-errors.jsonl",
	)
)

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

// CaptureCommandFileOutput captures command output in the supplied context buffer.
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

// RecordCommandExecution saves command execution history.
func RecordCommandExecution(
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

	duration := time.Since(startedAt).Milliseconds()
	executedAt := startedAt.UTC()

	if executionErr != nil {
		record := commandErrorRecord{
			Command:    commandName,
			Args:       security.RedactArgs(args),
			Status:     "failed",
			ExecutedAt: executedAt,
			DurationMS: duration,
		}

		record.Error.Code = "COMMAND_FAILED"
		record.Error.Message = security.RedactText(executionErr.Error())

		if stdout != "" {
			record.Error.Message += "\nOutput: " +
				security.RedactText(stdout)
		}

		if err := AppendRecords([]any{record}, commandErrorsFile); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"Could not save command error history: %v\n",
				err,
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
		Args:       security.RedactArgs(args),
		Status:     "completed",
		ExecutedAt: executedAt,
		DurationMS: duration,
		Output:     security.RedactText(stdout),
		OutputFile: outputFile,
	}

	if err := AppendRecords([]any{record}, commandResultsFile); err != nil {
		fmt.Fprintf(
			os.Stderr,
			"Could not save command result history: %v\n",
			err,
		)
	}
}

func AppendRecords(records []any, path string) error {
	if len(records) == 0 {
		return nil
	}

	file, err := logger.OpenLogFile(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)

	for _, record := range records {
		if err := encoder.Encode(record); err != nil {
			return fmt.Errorf("encode JSONL record: %w", err)
		}
	}

	return nil
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
