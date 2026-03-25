// Package main is the entry point for the rtbtr CLI.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/rtbtr/rtbtr-cli/internal/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		if errors.Is(err, cmd.ErrInvalidSignature) {
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
