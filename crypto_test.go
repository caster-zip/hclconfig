package hclconfig

import (
	"encoding/base64"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		t.Fatalf("key is not valid base64: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("key length = %d bytes, want 32", len(decoded))
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}

	plaintext := "super-secret-password"
	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	if ciphertext == plaintext {
		t.Fatal("ciphertext should differ from plaintext")
	}

	got, err := Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	if got != plaintext {
		t.Fatalf("Decrypt() = %q, want %q", got, plaintext)
	}
}

func TestEncryptProducesDifferentCiphertexts(t *testing.T) {
	key, _ := GenerateKey()
	plaintext := "same-value"

	c1, _ := Encrypt(plaintext, key)
	c2, _ := Encrypt(plaintext, key)

	if c1 == c2 {
		t.Fatal("encrypting the same plaintext twice should produce different ciphertexts")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()

	ciphertext, _ := Encrypt("secret", key1)

	_, err := Decrypt(ciphertext, key2)
	if err == nil {
		t.Fatal("Decrypt() with wrong key should return error")
	}
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	key, _ := GenerateKey()
	ciphertext, _ := Encrypt("secret", key)

	raw, _ := base64.StdEncoding.DecodeString(ciphertext)
	raw[len(raw)-1] ^= 0xff
	tampered := base64.StdEncoding.EncodeToString(raw)

	_, err := Decrypt(tampered, key)
	if err == nil {
		t.Fatal("Decrypt() with tampered ciphertext should return error")
	}
}

func TestDecryptBadBase64Ciphertext(t *testing.T) {
	key, _ := GenerateKey()
	_, err := Decrypt("not-valid-base64!!!", key)
	if err == nil {
		t.Fatal("Decrypt() with bad base64 ciphertext should return error")
	}
}

func TestDecryptTruncatedCiphertext(t *testing.T) {
	key, _ := GenerateKey()
	short := base64.StdEncoding.EncodeToString([]byte("tiny"))
	_, err := Decrypt(short, key)
	if err == nil {
		t.Fatal("Decrypt() with truncated ciphertext should return error")
	}
}

func TestEncryptBadKey(t *testing.T) {
	_, err := Encrypt("secret", "not-valid-base64!!!")
	if err == nil {
		t.Fatal("Encrypt() with bad base64 key should return error")
	}
}

func TestEncryptKeyWrongLength(t *testing.T) {
	shortKey := base64.StdEncoding.EncodeToString(make([]byte, 16))
	_, err := Encrypt("secret", shortKey)
	if err == nil {
		t.Fatal("Encrypt() with 16-byte key should return error")
	}

	longKey := base64.StdEncoding.EncodeToString(make([]byte, 64))
	_, err = Encrypt("secret", longKey)
	if err == nil {
		t.Fatal("Encrypt() with 64-byte key should return error")
	}
}

func TestDecryptBadKey(t *testing.T) {
	_, err := Decrypt("dGVzdA==", "not-valid-base64!!!")
	if err == nil {
		t.Fatal("Decrypt() with bad base64 key should return error")
	}
}

func TestDecryptKeyWrongLength(t *testing.T) {
	shortKey := base64.StdEncoding.EncodeToString(make([]byte, 16))
	_, err := Decrypt("dGVzdA==", shortKey)
	if err == nil {
		t.Fatal("Decrypt() with 16-byte key should return error")
	}
}
