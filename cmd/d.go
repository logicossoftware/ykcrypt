/*
Copyright © 2025 Logicos Software

d.go implements the 'd' command - a quick/shorthand version of 'decrypt'.

This command provides a simplified interface for common decryption use cases:
  - Minimal flags required (just the input file)
  - Automatic output filename (removes .ykc extension or adds .dec)
  - Optional in-place decryption with -F flag

The 'd' command is designed for everyday use, while 'decrypt' provides
the full command interface with explicit input/output flags.

Troubleshooting tips are included in the command help for common errors.
*/
package cmd

import (
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// dCmd represents the quick decrypt command.
// It provides a streamlined interface for the most common decryption scenarios.
var dCmd = &cobra.Command{
	Use:   "d [flags] <input> [output]",
	Short: "Quick decrypt a file",
	Long: `Quick decrypt a file using sensible defaults.

If output is not specified, it defaults to the input without .ykc extension.
You will be prompted for the PIV PIN and need to touch the YubiKey.

Use -F to decrypt in-place (overwrites the original file).

TROUBLESHOOTING:

  Got "security status not satisfied" (error 6982)?
    → Touch your YubiKey when it blinks! You have ~15 seconds after entering PIN.

  Got "verification failed" (error 63cx)?
    → Wrong PIN. The 'x' is retries left. After 3 fails, PIN is blocked.

  Got "authentication blocked" (error 6983)?
    → PIN is blocked. Use YubiKey Manager or 'ykman piv access unblock-pin'.

  Got "this doesn't look like an encrypted file"?
    → File is not encrypted or already decrypted. Check the filename!

Run 'ykcrypt decrypt --help' for a complete list of error codes.`,
	Example: `  # Decrypt file (creates secrets.txt from secrets.txt.ykc)
  ykcrypt d secrets.txt.ykc

  # Decrypt with custom output
  ykcrypt d secrets.txt.ykc decrypted.txt

  # Decrypt in-place (overwrites original)
  ykcrypt d -F secrets.txt.ykc`,
	Args: cobra.MinimumNArgs(1),
	Run:  runQuickDecrypt,
}

// init registers the 'd' command and configures its command-line flags.
// Flags: --force/-F for in-place decryption
func init() {
	rootCmd.AddCommand(dCmd)

	// In-place decryption flag (overwrites original file)
	dCmd.Flags().BoolP("force", "F", false, "Overwrite original file with decrypted version")
}

// runQuickDecrypt handles the 'd' command execution.
// It determines the output path and calls doDecrypt.
//
// Output path determination:
//  1. If second argument provided, use it
//  2. If input ends with .ykc, remove the extension
//  3. Otherwise, append .dec to avoid overwriting
//
// Behavior with -F flag:
//   - Decrypts to temp file, then replaces original
//   - Useful for decrypting in-place encrypted files
func runQuickDecrypt(cmd *cobra.Command, args []string) {
	// Extract flag values
	overwrite, _ := cmd.Flags().GetBool("force")
	reader, _ := cmd.Flags().GetString("reader")

	// Determine input and output paths
	inPath := args[0]

	// Try to derive output path from input path
	outPath := strings.TrimSuffix(inPath, ".ykc")
	if outPath == inPath {
		// Input didn't end with .ykc, add .dec to avoid overwriting
		outPath = inPath + ".dec"
	}
	if len(args) >= 2 {
		// Explicit output path provided
		outPath = args[1]
	}

	if overwrite {
		// In-place decryption: decrypt to temp file, then replace original
		tmpPath := inPath + ".dec.tmp"

		// Decrypt to temporary file
		doDecrypt(reader, inPath, tmpPath)

		// Remove original and rename temp to original
		if err := os.Remove(inPath); err != nil {
			ExitWithError(err)
		}
		if err := os.Rename(tmpPath, inPath); err != nil {
			ExitWithError(err)
		}
	} else {
		// Standard decryption to new file
		doDecrypt(reader, inPath, outPath)
	}
}
