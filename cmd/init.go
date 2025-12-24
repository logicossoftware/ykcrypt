/*
Copyright © 2025 Logicos Software

init.go implements the 'init' command for provisioning PIV slots.

This command generates a new EC key pair on the YubiKey's secure element
and stores a self-signed certificate containing the public key. The
certificate enables later retrieval of the public key for encryption
operations without requiring the YubiKey to perform cryptographic operations.

The generated key uses:
  - ECDH-capable elliptic curve key (P-256 or P-384)
  - PIN policy: Always required (protects against unauthorized use)
  - Touch policy: Always required (prevents remote/automated attacks)
*/
package cmd

import (
	"crypto/ecdsa"
	"fmt"
	"strings"

	"github.com/go-piv/piv-go/v2/piv"
	"github.com/spf13/cobra"
)

// initCmd represents the 'init' command for key provisioning.
// It generates a new EC key in a PIV slot and outputs a recipient
// string that can be used for encryption without the YubiKey present.
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Provision a PIV slot with an EC key",
	Long: `Provision a PIV slot with an EC key and store a certificate containing
the public key for later export.

This prints a recipient string that can be used with the encrypt command.
The recipient string format is: ykcrypt1:<slotHex>:<curveId>:<base64PublicKey>`,
	Example: `  # Provision key in default slot (9d)
  ykcrypt init

  # Provision key in specific slot with P-384 curve
  ykcrypt init --slot 9a --curve p384`,
	Run: runInit,
}

// init registers the 'init' command with the root command and configures
// its command-line flags for slot selection, curve type, and management key.
func init() {
	rootCmd.AddCommand(initCmd)

	// Configure command flags
	// --slot: PIV slot where the key will be generated (default: 9d = Key Management)
	initCmd.Flags().String("slot", "9d", `PIV slot: 9a, 9c, 9d, 9e (default: 9d "Key Management")`)
	// --curve: Elliptic curve to use for key generation
	initCmd.Flags().String("curve", "p256", "Curve: p256 or p384")
	// --mgmt-key: Management key required for key generation (24-byte hex or 'default')
	initCmd.Flags().String("mgmt-key", "default", "Management key hex (24 bytes) or 'default'")
}

// runInit executes the key provisioning process.
// It performs the following steps:
//  1. Parse and validate command-line arguments
//  2. Open connection to the YubiKey
//  3. Generate a new EC key in the specified PIV slot
//  4. Create and store a certificate containing the public key
//  5. Output the recipient string for use with encryption
//
// The recipient string format is: ykcrypt1:<slotHex>:<curveId>:<base64PublicKey>
func runInit(cmd *cobra.Command, args []string) {
	// Retrieve flag values
	reader, _ := cmd.Flags().GetString("reader")
	slotStr, _ := cmd.Flags().GetString("slot")
	curveStr, _ := cmd.Flags().GetString("curve")
	mgmtKeyHx, _ := cmd.Flags().GetString("mgmt-key")

	// Parse and validate the PIV slot
	slot, err := ParseSlot(slotStr)
	if err != nil {
		ExitWithError(err)
	}

	// Parse the management key (required for key generation)
	mgmtKey, err := ParseManagementKey(mgmtKeyHx)
	if err != nil {
		ExitWithError(err)
	}

	// Open connection to the YubiKey
	yk, closeFn, err := OpenYubiKey(reader)
	if err != nil {
		ExitWithError(err)
	}
	defer closeFn()

	// Determine the algorithm based on curve selection
	var alg piv.Algorithm
	switch strings.ToLower(curveStr) {
	case "p256", "ec256":
		alg = piv.AlgorithmEC256
	case "p384", "ec384":
		alg = piv.AlgorithmEC384
	default:
		ExitWithErrorMsg("unsupported curve %q (use p256 or p384)", curveStr)
	}

	// Configure key generation options
	// PIN and Touch policies are set to "Always" for maximum security
	keyOpts := piv.Key{
		Algorithm:   alg,
		PINPolicy:   piv.PINPolicyAlways,   // Require PIN for every operation
		TouchPolicy: piv.TouchPolicyAlways, // Require physical touch for every operation
	}

	// Generate the key on the YubiKey's secure element
	pub, err := yk.GenerateKey(mgmtKey, slot, keyOpts)
	if err != nil {
		ExitWithError(err)
	}

	// Verify we got an ECDSA public key
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		ExitWithErrorMsg("expected ECDSA public key, got %T", pub)
	}

	// Create a container certificate to store the public key
	// This allows retrieval of the public key without attestation
	_, cert, err := MakeContainerCert(ecdsaPub, "ykcrypt "+strings.ToUpper(slotStr))
	if err != nil {
		ExitWithError(err)
	}

	// Store the certificate in the same slot
	if err := yk.SetCertificate(mgmtKey, slot, cert); err != nil {
		ExitWithError(err)
	}

	// Generate and output the recipient string
	recipient, err := RecipientFromECDSAPublicKey(slot, ecdsaPub)
	if err != nil {
		ExitWithError(err)
	}

	fmt.Println(recipient)
}
