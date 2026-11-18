package ssh

import (
	"context"
	"testing"
)

func TestRunArgsHonorsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	executor := NewLocalExecutor()
	_, err := executor.RunArgs(ctx, "go", "version")
	if err == nil {
		t.Fatal("expected canceled context error")
	}
}
