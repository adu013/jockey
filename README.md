# jockey

# Description
A lightweight cryptographic engine library that combines **AES-256-GCM Authenticated Encryption** with **Argon2id Key Derivation** password stretching into a highly reusable, portable package.

## Security

*   **Defensive Key Stretching:** Utilizes **Argon2id** to force intensive memory (RAM) and multi-threaded CPU processing boundaries on password lookups, paralyzing hardware dictionary brute-force attacks.
*   **Sealed Authenticated Encryption (AEAD):** Implements **AES-256-GCM** to handle data scrambling. It generates cryptographically secure random 12-byte nonces dynamically and appends a 16-byte cryptographic signature tag (`HMAC`) to detect and block file tampering instantly.
*   **Zero-Knowledge Compliance:** Designed specifically to isolate secret values on client-side interfaces. The engine operates purely in volatile system RAM memory loops without caching plain text traces down onto physical disk drives.
*   **Zero CGO Dependencies:** Operates entirely over standard, native Go compiler toolchains. It features 100% portable Go compilation profiles (`CGO_ENABLED=0`), making it incredibly lightweight and cross-platform friendly for scratch Docker container clouds.

---

## Installation

This package can be installed with the go get command:

```bash
go get github.com/adu013/jockey
```

---

## Testing

Run the test engine inside terminal window:

```bash
go test -v -cover
```

---

## Sample Code

The following example shows how to configure your tuning properties, stretch a master password passphrase into an unbreakable key space, and securely encrypt and decrypt a sensitive application data string.

```go
package main

import (
	"fmt"
	"log"

	"github.com/adu013/jockey" // Import it here
)

func main() {
	masterPassword := "MyAbsoluteSuperSecretKey123!"
	systemSalt := "unique_application_system_salt_string"
	plainTextSecret := "confidential_database_payload_token_xyz"

	// Define your custom industrial Argon2id performance constraints profile
	tuningParams := jockey.CryptoParams{
		Memory:           64 * 1024, // Allocate 64MB of system RAM to block GPU guessing arrays
		Iterations:       3,         // Loop mathematical formulas 3 times
		ParallelThreads:  2,         // Split computation lanes concurrently over 2 threads
		KeyLength:        32,        // Stretch output key uniformly to 32 Bytes (256-bit AES)
	}

	fmt.Println("# Crunching key stretching parameters locally...")
	derivedKey := jockey.DeriveMasterKey(masterPassword, systemSalt, tuningParams)
	fmt.Printf("  Key Derived Successfully: %x\n\n", derivedKey)

	// Encrypt your plain text payload into raw encrypted binary bytes
	fmt.Println("# Encrypting secret payload capsule...")
	cipherText, nonce, err := jockey.Encrypt(plainTextSecret, derivedKey)
	if err != nil {
		log.Fatalf("  Encryption failed: %v", err)
	}
	fmt.Printf("  Encrypted Ciphertext Blocks: %x\n", cipherText)
	fmt.Printf("  Unique Random 12-Byte Nonce: %x\n\n", nonce)

	// Decrypt your scrambled data blocks back into a readable string container
	fmt.Println("# Validating authenticity tags and executing decryption...")
	decryptedString, err := jockey.Decrypt(cipherText, nonce, derivedKey)
	if err != nil {
		log.Fatalf("  Security Alert! Tampering detected or bad key: %v", err)
	}
	fmt.Printf("  Success! Restored Plaintext String: %s\n", decryptedString)
}
```

---
