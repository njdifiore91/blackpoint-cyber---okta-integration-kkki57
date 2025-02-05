// Package common provides shared functionality for the BlackPoint CLI application.
// This file defines version information and build details for version tracking and identification.
package common

import (
	"fmt"
	"runtime"
)

// Version information - populated during build
var (
	// Version represents the semantic version of the CLI application
	Version = "1.0.0"
	// GitCommit represents the Git commit hash from which the CLI was built
	GitCommit = ""
	// BuildDate represents the ISO 8601 formatted timestamp when the CLI was built
	BuildDate = ""
	// GoVersion represents the Go runtime version used to build the CLI
	GoVersion = runtime.Version()
	// Platform represents the operating system and architecture combination
	Platform = fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
)

// GetVersionInfo returns a formatted multi-line string containing comprehensive
// version and build information for the CLI application.
func GetVersionInfo() string {
	commit := GitCommit
	if commit == "" {
		commit = "development"
	}

	buildDate := BuildDate
	if buildDate == "" {
		buildDate = "unknown"
	}

	return fmt.Sprintf(
		"BlackPoint Security CLI\n"+
			"Version:    %s\n"+
			"Commit:     %s\n"+
			"Built:      %s\n"+
			"Go Version: %s\n"+
			"Platform:   %s\n",
		Version,
		commit,
		buildDate,
		GoVersion,
		Platform,
	)
}

// GetVersion returns the semantic version number of the CLI application
// for programmatic version checks and compatibility verification.
func GetVersion() string {
	return Version
}