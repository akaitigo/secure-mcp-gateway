package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("secure-mcp-gateway starting...")
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// TODO: implement proxy server
	return nil
}
