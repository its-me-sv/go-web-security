package storage

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

type EncryptedPayload struct {
	Nonce      []byte
	AuthTag    []byte
	Ciphertext []byte
}

const authTagSize = 16

func Encrypt(plaintext []byte, key [32]byte) (EncryptedPayload, error) {
	aead, err := buildAEADFromKey(key)
	if err != nil {
		return EncryptedPayload{}, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedPayload{}, err
	}

	sealed := aead.Seal(nil, nonce, plaintext, nil)
	fullLen := len(sealed)
	cipherText, authTag := sealed[:fullLen-authTagSize], sealed[fullLen-authTagSize:]

	return EncryptedPayload{
		Nonce:      nonce,
		AuthTag:    authTag,
		Ciphertext: cipherText,
	}, nil
}

func Decrypt(payload EncryptedPayload, key [32]byte) ([]byte, error) {
	if len(payload.Nonce) != 12 {
		return nil, errors.New("inavlid nonce")
	}
	if len(payload.AuthTag) != authTagSize {
		return nil, errors.New("inavlid authTag")
	}

	aead, err := buildAEADFromKey(key)
	if err != nil {
		return nil, err
	}

	cipherText := bytes.Join([][]byte{payload.Ciphertext, payload.AuthTag}, []byte(""))
	return aead.Open(nil, payload.Nonce, cipherText, nil)
}

func buildAEADFromKey(key [32]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}
