// Package blackpoint implements the root command and core functionality for the BlackPoint CLI
package blackpoint

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"blackpoint/cli/pkg/common/constants"
	"blackpoint/cli/pkg/common/logging"
	"blackpoint/cli/pkg/common/version"
)

var (
	// rootCmd represents the base command when called without any subcommands
	rootCmd = &cobra.Command{
		Use:   "blackpoint",
		Short: "BlackPoint Security Integration Framework CLI",
		Long: `BlackPoint CLI provides command-line interface for managing security platform integrations,
data collection, configuration, and monitoring of the BlackPoint Security Integration Framework.

Complete documentation is available at https://docs.blackpoint.security`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Global flags
	cfgFile      string
	logLevel     string
	outputFormat string
)

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		// Log error with proper formatting based on output format
		if outputFormat == "json" {
			fmt.Fprintf(os.Stderr, `{"error": "%s", "code": "%s"}`, err.Error(), "E1000")
		} else {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err.Error())
		}
		return err
	}
	return nil
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is "+constants.DefaultConfigPath+")")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", constants.DefaultLogLevel, 
		fmt.Sprintf("set logging level (%s)", strings.Join(constants.ValidLogLevels, ", ")))
	rootCmd.PersistentFlags().StringVar(&outputFormat, "output", constants.DefaultOutputFormat, 
		fmt.Sprintf("output format (%s)", strings.Join(constants.ValidOutputFormats, ", ")))

	// Version command
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Display version information",
		Run:   runVersion,
	})

	// Add required subcommands
	// Note: These would be implemented in separate files
	// rootCmd.AddCommand(newIntegrateCmd())
	// rootCmd.AddCommand(newCollectCmd())
	// rootCmd.AddCommand(newConfigureCmd())
	// rootCmd.AddCommand(newMonitorCmd())

	// Enable command completion
	rootCmd.CompletionOptions.DisableDefaultCmd = true
}

// initConfig reads in config file and ENV variables if set
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		// Search config in home directory with name ".blackpoint" (without extension)
		viper.AddConfigPath(filepath.Join(home, ".blackpoint"))
		viper.SetConfigType("yaml")
		viper.SetConfigName("config")
	}

	// Read config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			fmt.Fprintf(os.Stderr, "Error reading config file: %v\n", err)
			os.Exit(1)
		}
	}

	// Check config file permissions
	if viper.ConfigFileUsed() != "" {
		info, err := os.Stat(viper.ConfigFileUsed())
		if err == nil {
			mode := info.Mode().Perm()
			if mode != 0600 && mode != 0400 {
				fmt.Fprintf(os.Stderr, "Warning: Config file has insecure permissions %v, should be 600 or 400\n", mode)
			}
		}
	}

	// Environment variables
	viper.SetEnvPrefix("BLACKPOINT")
	viper.AutomaticEnv()

	// Initialize logger
	logConfig := &logging.LogConfig{
		Level:  logLevel,
		Format: outputFormat,
	}
	if err := logging.InitLogger(logLevel, outputFormat, logConfig); err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing logger: %v\n", err)
		os.Exit(1)
	}

	// Validate output format
	if !isValidOutputFormat(outputFormat) {
		fmt.Fprintf(os.Stderr, "Error: Invalid output format. Must be one of: %s\n", 
			strings.Join(constants.ValidOutputFormats, ", "))
		os.Exit(1)
	}
}

// runVersion displays version information in the configured output format
func runVersion(cmd *cobra.Command, args []string) {
	if outputFormat == "json" {
		fmt.Printf(`{
  "version": "%s",
  "commit": "%s",
  "build_date": "%s",
  "go_version": "%s",
  "platform": "%s"
}`, version.GetVersion(), version.GitCommit, version.BuildDate, version.GoVersion, version.Platform)
	} else {
		fmt.Print(version.GetVersionInfo())
	}
}

// isValidOutputFormat checks if the provided output format is supported
func isValidOutputFormat(format string) bool {
	for _, validFormat := range constants.ValidOutputFormats {
		if format == validFormat {
			return true
		}
	}
	return false
}