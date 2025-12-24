/*
Copyright © 2025 Logicos Software

version.go implements the 'version' command.

This command displays version information for ykcrypt, including:
  - Semantic version number
  - Git commit hash
  - Build timestamp
  - Go compiler version

Version information is embedded at build time via ldflags:

	go build -ldflags "-X ykcrypt/cmd.Version=1.0.0 \
	                   -X ykcrypt/cmd.GitCommit=$(git rev-parse HEAD) \
	                   -X ykcrypt/cmd.BuildTime=$(date -Iseconds) \
	                   -X ykcrypt/cmd.GoVersion=$(go version)"
*/
package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

// versionCmd represents the 'version' command.
// It displays build and version information for ykcrypt.
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version information",
	Long:  `Print the version information for ykcrypt.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Display version information
		fmt.Println("ykcrypt - YubiKey-based file encryption tool")
		fmt.Printf("Version:    %s\n", Version)
		fmt.Printf("Git Commit: %s\n", GitCommit)
		fmt.Printf("Built:      %s\n", BuildTime)
		fmt.Printf("Go Version: %s\n", GoVersion)
		fmt.Println()
		// Display copyright with current year
		fmt.Printf("Copyright © 2024-%d Logicos Software\n", time.Now().Year())
		fmt.Println("Licensed under the MIT License")
		fmt.Println("https://github.com/logicossoftware/ykcrypt")
	},
}

// init registers the 'version' command with the root command.
func init() {
	rootCmd.AddCommand(versionCmd)
}
