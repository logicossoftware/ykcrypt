/*
Copyright © 2025 Logicos Software

Package cmd implements all CLI commands for ykcrypt using the Cobra library.

This package provides:
  - init: Provision PIV slots with EC keys
  - encrypt/e: Encrypt files using ECDH key agreement
  - decrypt/d: Decrypt files using YubiKey
  - export: Export recipient public key strings
  - version: Display version information

All cryptographic operations use industry-standard algorithms:
  - ECDH with P-256 or P-384 curves for key agreement
  - XChaCha20-Poly1305 or AES-256-GCM for symmetric encryption
  - HKDF-SHA256 for key derivation
  - Argon2id for passphrase-based key stretching
*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands.
// It serves as the parent for all ykcrypt subcommands and defines
// global flags that are inherited by child commands.
var rootCmd = &cobra.Command{
	Use:   "ykcrypt",
	Short: "File encryption using a YubiKey PIV ECDH key agreement key",
	Long: `ykcrypt is a command-line tool that encrypts/decrypts files using a 
YubiKey PIV ECDH key agreement key as the hardware-root secret.

Security model:
  - Encryption uses ephemeral ECDH against the YubiKey slot public key
  - Encryption can be done without the YubiKey if you have the recipient string
  - Decryption requires the YubiKey (PIN + touch)
  - Optional passphrase as second factor

Quick usage:
  ykcrypt init              # Provision key in slot 9d
  ykcrypt e secrets.txt     # Encrypt (creates secrets.txt.ykc)
  ykcrypt d secrets.txt.ykc # Decrypt (prompts for PIN + touch)
  ykcrypt e -F secrets.txt  # Encrypt in-place (overwrites original)`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
// If an error occurs during command execution, the program exits with status code 1.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

// init registers global flags that are available to all subcommands.
// The --reader flag allows users to specify a particular PC/SC reader
// when multiple YubiKeys or smart card readers are connected.
func init() {
	// Global flags - available to all subcommands
	// The reader flag allows specifying a particular YubiKey when multiple are present
	rootCmd.PersistentFlags().String("reader", "", "PC/SC reader name (default: first YubiKey found)")
}
