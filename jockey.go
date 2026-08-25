// Package jockey provides cryptographic utilities
// combining AES-256-GCM authenticated encryption with Argon2id key derivation.
package jockey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

// CryptoParams struct holds the structural configuration properties required to execute
// a memory-hard and computation-intensive Argon2id password stretching routine.
type CryptoParams struct {
	Memory          uint32 // Amount of memory (RAM) that the algorithm will use, measured in KB (16MB = 16 * 1024)
	Iterations      uint32 // Nos of pass
	ParallelThreads uint8  // Nos of parallel threads
	KeyLength       uint32 // // Desired Keylength to be generated
}

// DeriveMasterKey func stretches a human passkey into a uniform master key utilizing the Argon2id algorithm.
// It returns a byte slice matching the requested KeyLength parameter.
func DeriveMasterKey(masterPassword string, systemSalt string, params CryptoParams) []byte {
	return argon2.IDKey(
		[]byte(masterPassword),
		[]byte(systemSalt),
		params.Iterations,
		params.Memory,
		params.ParallelThreads,
		params.KeyLength,
	)
}

// Encrypt func encrypts a plaintext string payload using AES-256-GCM authenticated encryption.
// It builds and return the encrpyed byte slice and a unique 12-byte initialization vector nonce.
func Encrypt(plainText string, masterKey []byte) (cipherText []byte, nonce []byte, err error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	cipherText = aesGCM.Seal(nil, nonce, []byte(plainText), nil)
	return cipherText, nonce, nil
}

// Decrypt func processes an encrypted payload and verifies its 16-byte authentication signature.
// If the check matches, it restores and returns the raw ciphertext bytes back into a readable plaintext string.
func Decrypt(cipherText []byte, nonce []byte, masterKey []byte) (string, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(nonce) != aesGCM.NonceSize() {
		return "", errors.New("Invalid cryptographic initialization nonce size.")
	}

	plainBytes, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", errors.New("Authentication check failed. Data is corrupted or tampered with.")
	}

	return string(plainBytes), nil
}
