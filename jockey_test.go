package jockey

import (
	"bytes"
	"testing"
)

// TestDeriveMasterKey ensures that the Argon2id stretching engine is deterministic
// (meaning the same password and salt must ALWAYS yield the exact same 32-byte key)
func TestDeriveMasterKey(t *testing.T) {
	password := "SecretPass123!"
	salt := "test_system_salt_string"
	params := CryptoParams{
		Memory:          16 * 1024, // Using lower values for fast testing speeds
		Iterations:      1,         // One pass for testing
		ParallelThreads: 1,         // One thread for testing
		KeyLength:       32,
	}

	key1 := DeriveMasterKey(password, salt, params)
	key2 := DeriveMasterKey(password, salt, params)

	if len(key1) != 32 {
		t.Errorf("Expected derived key length of 32 bytes, but got %d", len(key1))
	}

	// Verify both keys are identical
	for i := range key1 {
		if key1[i] != key2[i] {
			t.Fatalf("Cryptographic desync: Derived keys are not identical for the same input!")
		}
	}
}

// TestUnmatchDeriveMasterKey ensures that the Argon2id stretching engine
// same password and different salt yield the different 32-byte keys
func TestUnmatchDeriveMasterKey(t *testing.T) {
	password := "SecretPass123!"
	salt1 := "test_system_salt_strings"
	salt2 := "this_is_a_different_salt"
	params := CryptoParams{
		Memory:          16 * 1024, // Using lower values for fast testing speeds
		Iterations:      1,         // One pass for testing
		ParallelThreads: 1,         // One thread for testing
		KeyLength:       32,
	}

	key1 := DeriveMasterKey(password, salt1, params)
	key2 := DeriveMasterKey(password, salt2, params)

	if len(key1) != 32 {
		t.Errorf("Expected derived key length of 32 bytes, but got %d", len(key1))
	}

	if len(key2) != 32 {
		t.Errorf("Expected derived key length of 32 bytes, but got %d", len(key1))
	}

	// Verify that the keys are different (not identical)
	if bytes.Equal(key1, key2) {
		t.Fatalf("Cryptographic desync: Derived keys are identical for different inputs!")
	}
}

// TestEncryptDecrypt Lifecycle ensures that data can be cleanly scrambled and restored perfectly
func TestEncryptDecryptLifecycle(t *testing.T) {
	secretMessage := "This is a highly confidential string!"
	mockMasterKey := []byte("0123456789abcdef0123456789abcdef") // Mock 32-byte AES key

	// TEST: Execute Encryption
	cipherText, nonce, err := Encrypt(secretMessage, mockMasterKey)
	if err != nil {
		t.Fatalf("Encryption failed unexpectedly: %v", err)
	}

	if len(nonce) != 12 {
		t.Errorf("Expected standard AES-GCM nonce size of 12, got %d", len(nonce))
	}

	// TEST: Execute Decryption
	decryptedMessage, err := Decrypt(cipherText, nonce, mockMasterKey)
	if err != nil {
		t.Fatalf("Decryption failed unexpectedly: %v", err)
	}

	if decryptedMessage != secretMessage {
		t.Errorf("Data corruption: Expected '%s', but recovered '%s'", secretMessage, decryptedMessage)
	}
}

// TestTamperDetection verifies that our AES-GCM Authentication works correctly
// and blocks decryption if an attacker changes even a single bit of the file data.
func TestTamperDetection(t *testing.T) {
	secretMessage := "Protected Data"
	mockMasterKey := []byte("0123456789abcdef0123456789abcdef")

	cipherText, nonce, _ := Encrypt(secretMessage, mockMasterKey)

	// TAMPER SIMULATION: Purposefully flip the very first byte of the encrypted ciphertext data
	cipherText[0] ^= 0xFF

	// Attempt decryption on the corrupted data block
	_, err := Decrypt(cipherText, nonce, mockMasterKey)

	// The test PASSES if an error is returned. It proves the attack is blocked.
	if err == nil {
		t.Error("SECURITY HOLE: Decrypt succeeded on corrupted data! Authentication verification failed to block tampering.")
	}
}
