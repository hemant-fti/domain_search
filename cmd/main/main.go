package main

import (
	"domain-search/cmd/app"
	"os"
)

func main() {
	if err := app.RunApplication(); err != nil {
		os.Exit(1)
	}
}
