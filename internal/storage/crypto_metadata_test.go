package storage

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSaveAndLoadCryptoMetadata(t *testing.T) {
	tempDir := t.TempDir()
	metaPath := filepath.Join(tempDir, CryptoMetadataFilename)

	key := make([]byte, ExpectedKeyLength)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	nonce := make([]byte, ExpectedNonceLength)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("failed to generate random nonce: %v", err)
	}

	if err := SaveCryptoMetadata(metaPath, key, nonce); err != nil {
		t.Fatalf("SaveCryptoMetadata failed: %v", err)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(metaPath)
		if err != nil {
			t.Fatalf("failed to stat metadata file: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Errorf("expected permissions 0600, got %04o", perm)
		}
	}

	loadedKey, loadedNonce, err := LoadCryptoMetadata(metaPath)
	if err != nil {
		t.Fatalf("LoadCryptoMetadata failed: %v", err)
	}

	if !bytes.Equal(key, loadedKey) {
		t.Errorf("loaded key does not match original key\nexpected: %x\ngot:      %x", key, loadedKey)
	}

	if !bytes.Equal(nonce, loadedNonce) {
		t.Errorf("loaded nonce does not match original nonce\nexpected: %x\ngot:      %x", nonce, loadedNonce)
	}
}

func TestSaveAndLoadCryptoMetadata_Validations(t *testing.T) {
	tempDir := t.TempDir()
	metaPath := filepath.Join(tempDir, "invalid_meta.json")

	t.Run("SaveInvalidKeyLength", func(t *testing.T) {
		err := SaveCryptoMetadata(metaPath, make([]byte, 16), make([]byte, ExpectedNonceLength))
		if err == nil {
			t.Fatal("expected error on 16-byte key, got nil")
		}
	})

	t.Run("SaveInvalidNonceLength", func(t *testing.T) {
		err := SaveCryptoMetadata(metaPath, make([]byte, ExpectedKeyLength), make([]byte, 8))
		if err == nil {
			t.Fatal("expected error on 8-byte nonce, got nil")
		}
	})

	t.Run("LoadNonExistentFile", func(t *testing.T) {
		_, _, err := LoadCryptoMetadata(filepath.Join(tempDir, "non_existent.json"))
		if err == nil {
			t.Fatal("expected error for non existent file, got nil")
		}
	})

	t.Run("LoadInvalidKeyLength", func(t *testing.T) {
		invalidJSON := `{
			"algorithm": "AES-256-GCM",
			"key_hex": "abcd",
			"nonce_hex": "0102030405060708090a0b0c",
			"auth_tag_size": 16
		}`
		p := filepath.Join(tempDir, "short_key.json")
		if err := os.WriteFile(p, []byte(invalidJSON), 0600); err != nil {
			t.Fatal(err)
		}
		_, _, err := LoadCryptoMetadata(p)
		if err == nil {
			t.Fatal("expected error on short key, got nil")
		}
	})

	t.Run("LoadInvalidNonceLength", func(t *testing.T) {
		validKeyHex := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
		invalidJSON := `{
			"algorithm": "AES-256-GCM",
			"key_hex": "` + validKeyHex + `",
			"nonce_hex": "abcd",
			"auth_tag_size": 16
		}`
		p := filepath.Join(tempDir, "short_nonce.json")
		if err := os.WriteFile(p, []byte(invalidJSON), 0600); err != nil {
			t.Fatal(err)
		}
		_, _, err := LoadCryptoMetadata(p)
		if err == nil {
			t.Fatal("expected error on short nonce, got nil")
		}
	})

	t.Run("LoadInvalidAlgorithm", func(t *testing.T) {
		invalidJSON := `{
			"algorithm": "DES-EDE3-CBC",
			"key_hex": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
			"nonce_hex": "0102030405060708090a0b0c",
			"auth_tag_size": 16
		}`
		p := filepath.Join(tempDir, "bad_algo.json")
		if err := os.WriteFile(p, []byte(invalidJSON), 0600); err != nil {
			t.Fatal(err)
		}
		_, _, err := LoadCryptoMetadata(p)
		if err == nil {
			t.Fatal("expected error on unsupported algorithm, got nil")
		}
	})
}

func TestSaveCiphertext(t *testing.T) {
	tempDir := t.TempDir()
	cipherPath := filepath.Join(tempDir, EncryptedLogFilename)

	data := []byte("encrypted_raw_binary_content")
	if err := SaveCiphertext(cipherPath, data); err != nil {
		t.Fatalf("SaveCiphertext failed: %v", err)
	}

	read, err := os.ReadFile(cipherPath)
	if err != nil {
		t.Fatalf("failed to read ciphertext: %v", err)
	}

	if !bytes.Equal(data, read) {
		t.Errorf("read ciphertext does not match written ciphertext")
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(cipherPath)
		if err != nil {
			t.Fatalf("failed to stat ciphertext file: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Errorf("expected permissions 0600, got %04o", perm)
		}
	}
}
