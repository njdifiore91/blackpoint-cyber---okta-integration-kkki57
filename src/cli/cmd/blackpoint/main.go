// Package blackpoint provides the main entry point for the BlackPoint CLI application
package blackpoint

import (
	"fmt"
	"os"
	"runtime/debug"

	"blackpoint/cli/pkg/common/constants"
	"blackpoint/cli/pkg/common/errors"
	"blackpoint/cli/pkg/common/logging"
)

// Exit codes for the CLI application
const (
	exitCodeSuccess = constants.ExitCodeSuccess
	exitCodeError   = constants.ExitCodeError
	exitCodePanic   = 2 // Special case for panic recovery
)

func main() {
	// Initialize panic recovery to ensure graceful handling of unexpected errors
	defer func() {
		if r := recover(); r != nil {
			// Get stack trace for panic
			stack := debug.Stack()
			
			// Create a CLI error for the panic
			err := errors.NewCLIError(
				"E9999",
				fmt.Sprintf("Unexpected panic occurred: %v", r),
				nil,
			)

			// Log the panic with stack trace if logging is initialized
			if logger := logging.GetLogger(); logger != nil {
				logger.Error("CLI panic occurred",
					fmt.Errorf("%v", r),
					map[string]interface{}{
						"stack_trace": string(stack),
					},
				)
			} else {
				// Fallback to stderr if logger is not initialized
				fmt.Fprintf(os.Stderr, "Fatal error: %v\nStack trace:\n%s\n", r, stack)
			}

			// Exit with panic code
			os.Exit(exitCodePanic)
		}
	}()

	// Initialize logging with default configuration
	logConfig := &logging.LogConfig{
		Level:         constants.DefaultLogLevel,
		Format:        constants.DefaultOutputFormat,
		RetentionDays: 30,
		RotationSize:  10 * 1024 * 1024, // 10MB
	}

	if err := logging.InitLogger(constants.DefaultLogLevel, constants.DefaultOutputFormat, logConfig); err != nil {
		// If logging initialization fails, write to stderr and exit
		fmt.Fprintf(os.Stderr, "Failed to initialize logging: %v\n", err)
		os.Exit(exitCodeError)
	}

	// Get logger instance for main function
	logger := logging.GetLogger()

	// Log startup information
	logger.Info("Starting BlackPoint CLI",
		map[string]interface{}{
			"version": version.GetVersion(),
			"pid":     os.Getpid(),
		},
	)

	// Execute the root command
	if err := Execute(); err != nil {
		// Log the error with appropriate context
		var cliErr *errors.CLIError
		if errors.As(err, &cliErr) {
			logger.Error("Command execution failed",
				err,
				map[string]interface{}{
					"error_code": cliErr.Code,
				},
			)
		} else {
			logger.Error("Command execution failed with non-CLI error",
				err,
				nil,
			)
		}

		// Exit with error code
		os.Exit(exitCodeError)
	}

	// Log successful completion
	logger.Info("CLI execution completed successfully", nil)
	os.Exit(exitCodeSuccess)
}