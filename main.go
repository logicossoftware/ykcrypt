/*
Copyright © 2025 Logicos Software

ykcrypt - YubiKey-based File Encryption Tool

This is the main entry point for the ykcrypt command-line tool.
ykcrypt provides secure file encryption using YubiKey PIV ECDH
key agreement, combining hardware security with modern cryptography.

Security Model:
  - Uses ECDH key agreement with YubiKey-stored private keys
  - Supports XChaCha20-Poly1305 and AES-256-GCM ciphers
  - Optional passphrase as second factor using Argon2id
  - Requires PIN and physical touch for decryption
*/
package main

import "ykcrypt/cmd"

// main is the entry point for the ykcrypt application.
// It delegates all command handling to the cmd package which uses
// the Cobra library for CLI argument parsing and command execution.
func main() {
	cmd.Execute()
}
