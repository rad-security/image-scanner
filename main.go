package main

import (
	"os"

	"github.com/rad-security/image-scanner/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
