package main

import (
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/Hyodar/azure-tdx-verifier/utils/formatter"
)

func main() {
	logger := slog.New(
		slog.NewJSONHandler(
			os.Stdout,
			&slog.HandlerOptions{Level: slog.LevelDebug},
		),
	)

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <input_file>\n", os.Args[0])
		os.Exit(1)
	}

	inputFilename := os.Args[1]
	log.Printf("Processing input file: %s", inputFilename)

	formatter := formatter.NewAzureTDXFormatterWithLogger(logger)
	output, err := formatter.FormatFile(inputFilename)
	if err != nil {
		log.Fatalf("Failed to format attestation data: %v", err)
	}

	logger.Info("Formatting output data...")
	jsonOutput, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		logger.Error("Failed to marshal output JSON", "error", err)
		os.Exit(1)
	}

	fmt.Println(string(jsonOutput))
}
