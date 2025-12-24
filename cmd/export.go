/*
Copyright © 2025 Logicos Software

export.go implements the 'export' command for exporting recipient strings.

The recipient string contains the public key information needed to encrypt
files for a particular YubiKey. Once exported, the recipient string can be:
  - Shared with others who want to encrypt files for you
  - Stored in a configuration file for automated encryption
  - Used on systems where the YubiKey is not available

The recipient string format is: ykcrypt1:<slotHex>:<curveId>:<base64PublicKey>

This allows encryption without the YubiKey present - only decryption
requires the physical YubiKey (with PIN and touch).
*/
package cmd

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/spf13/cobra"
)

// exportCmd represents the 'export' command.
// It retrieves and outputs the recipient string for a PIV slot.
var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export the recipient string (public key) for a slot",
	Long: `Export the recipient string (public key) for a PIV slot.

The recipient string can be used with the encrypt command to encrypt
files without having the YubiKey present.`,
	Example: `  # Export recipient from default slot (9d)
  ykcrypt export

  # Export from specific slot and save to file
  ykcrypt export --slot 9a > recipient.txt`,
	Run: runExport,
}

// init registers the 'export' command and configures its command-line flags.
// Flags: --slot for specifying which PIV slot to export from
func init() {
	rootCmd.AddCommand(exportCmd)

	// PIV slot to export from (default: 9d = Key Management)
	exportCmd.Flags().String("slot", "9d", `PIV slot: 9a, 9c, 9d, 9e (default: 9d "Key Management")`)
}

// runExport handles the 'export' command execution.
// It retrieves the public key from the specified PIV slot and outputs
// the recipient string that can be used for encryption.
//
// The function attempts to read the certificate from the slot first,
// falling back to attestation if no certificate is present.
func runExport(cmd *cobra.Command, args []string) {
	// Extract flag values
	reader, _ := cmd.Flags().GetString("reader")
	slotStr, _ := cmd.Flags().GetString("slot")

	// Parse and validate the PIV slot
	slot, err := ParseSlot(slotStr)
	if err != nil {
		ExitWithError(err)
	}

	// Open connection to the YubiKey
	yk, closeFn, err := OpenYubiKey(reader)
	if err != nil {
		ExitWithError(err)
	}
	defer closeFn()

	// Try to get certificate from the slot
	cert, err := yk.Certificate(slot)
	if err != nil {
		// Fallback to attestation if no certificate is present
		// Attestation generates a certificate signed by the YubiKey's attestation key
		cert, err = yk.Attest(slot)
		if err != nil {
			ExitWithError(err)
		}
	}

	// Verify the certificate contains an ECDSA public key
	ecdsaPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		ExitWithErrorMsg("slot certificate public key is %T, expected *ecdsa.PublicKey", cert.PublicKey)
	}

	// Generate the recipient string from the public key
	recipient, err := RecipientFromECDSAPublicKey(slot, ecdsaPub)
	if err != nil {
		ExitWithError(err)
	}

	// Output the recipient string
	fmt.Println(recipient)
}
