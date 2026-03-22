// Package main is the entry point for the rtbtr CLI.
package main

import (
	"fmt"
	"os"

	"github.com/rtbtr/rtbtr-cli/internal/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
