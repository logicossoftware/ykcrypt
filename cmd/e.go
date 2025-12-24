/*
Copyright © 2025 Logicos Software

e.go implements the 'e' command - a quick/shorthand version of 'encrypt'.

This command provides a simplified interface for common encryption use cases:
  - Minimal flags required (just the input file)
  - Automatic output filename (adds .ykc extension)
  - Uses sensible defaults (slot 9d, ChaCha20, 1 MiB chunks)
  - Optional in-place encryption with -F flag

The 'e' command is designed for everyday use, while 'encrypt' provides
full control over all encryption parameters.
*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// eCmd represents the quick encrypt command.
// It provides a streamlined interface for the most common encryption scenarios.
var eCmd = &cobra.Command{
	Use:   "e [flags] <input> [output]",
	Short: "Quick encrypt a file",
	Long: `Quick encrypt a file using sensible defaults.

Uses the YubiKey in slot 9d to get the recipient public key.
If output is not specified, it defaults to <input>.ykc.

Use -F to encrypt in-place (overwrites the original file).`,
	Example: `  # Encrypt file (creates secrets.txt.ykc)
  ykcrypt e secrets.txt

  # Encrypt with custom output
  ykcrypt e secrets.txt encrypted.ykc

  # Encrypt in-place (overwrites original)
  ykcrypt e -F secrets.txt

  # Encrypt using AES-256-GCM
  ykcrypt e --cipher aes secrets.txt`,
	Args: cobra.MinimumNArgs(1),
	Run:  runQuickEncrypt,
}

// init registers the 'e' command and configures its command-line flags.
// Flags: --force/-F for in-place encryption, --cipher/-c for cipher selection
func init() {
	rootCmd.AddCommand(eCmd)

	// In-place encryption flag (overwrites original file)
	eCmd.Flags().BoolP("force", "F", false, "Overwrite original file with encrypted version")
	// Cipher selection (default: XChaCha20-Poly1305)
	eCmd.Flags().StringP("cipher", "c", "chacha", "Cipher: 'chacha' (XChaCha20-Poly1305) or 'aes' (AES-256-GCM)")
}

// runQuickEncrypt handles the 'e' command execution.
// It determines the output path and calls doEncrypt with default settings.
//
// Behavior:
//   - With -F: Encrypts to temp file, then replaces original
//   - Without -F: Creates new .ykc file (or uses second argument as output)
//
// Default settings:
//   - Slot: 9d (Key Management)
//   - No passphrase
//   - Chunk size: 1 MiB
func runQuickEncrypt(cmd *cobra.Command, args []string) {
	// Extract flag values
	overwrite, _ := cmd.Flags().GetBool("force")
	reader, _ := cmd.Flags().GetString("reader")
	cipherName, _ := cmd.Flags().GetString("cipher")

	// Determine input and output paths
	inPath := args[0]
	outPath := inPath + ".ykc"
	if len(args) >= 2 {
		outPath = args[1]
	}

	if overwrite {
		// In-place encryption: encrypt to temp file, then replace original
		tmpPath := inPath + ".ykc.tmp"

		// Encrypt to temporary file
		doEncrypt(reader, inPath, tmpPath, "", "9d", false, 1<<20, cipherName)

		// Remove original and rename temp to original
		if err := os.Remove(inPath); err != nil {
			ExitWithError(err)
		}
		if err := os.Rename(tmpPath, inPath); err != nil {
			ExitWithError(err)
		}
	} else {
		// Standard encryption to new file
		doEncrypt(reader, inPath, outPath, "", "9d", false, 1<<20, cipherName)
	}
}
