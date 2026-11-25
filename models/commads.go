package models

import "time"

type CommandOutputOptions struct {
	Jsonl   bool
	Pretty  bool
	Compact bool
	Timeout time.Duration
	Output  string
}

type CommandResult struct {
	Value any
	Human string
}

type CommandSpec struct {
	Name string
	Args []string
}
