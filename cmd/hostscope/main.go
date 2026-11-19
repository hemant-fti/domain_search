package main

import "os"

func main() {
	if err := runApplication(); err != nil {
		os.Exit(1)
	}
}
