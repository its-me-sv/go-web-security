package passwords

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	MaxLength  = 128
	SaltLength = 16
	KeyLength  = 32
)

func Hash(password string) (string, error) {
	if utf8.RuneCountInString(password) > MaxLength {
		return "", fmt.Errorf("password must not exceed %d characters", MaxLength)
	}

	salt := make([]byte, SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	derivedKey := argon2.IDKey([]byte(password), salt, 2, 19*1024, 1, KeyLength)
	hash := encodeArgon2idHash(argon2idHash{
		version:     argon2.Version,
		memoryKiB:   19 * 1024,
		iterations:  2,
		parallelism: 1,
		salt:        salt,
		derivedKey:  derivedKey,
	})

	return hash, nil
}

func Verify(password, encodedHash string) bool {
	if utf8.RuneCountInString(password) > MaxLength {
		return false
	}

	if expectedHash, ok := decodeLegacyHash(encodedHash); ok {
		candidateHash := sha256.Sum256([]byte(password))
		return subtle.ConstantTimeCompare(candidateHash[:], expectedHash) == 1
	}

	argonHash, ok := parseArgon2idHash(encodedHash)
	if !ok || argonHash.version != argon2.Version {
		return false
	}

	candidateHash := argon2.IDKey(
		[]byte(password),
		argonHash.salt,
		argonHash.iterations,
		argonHash.memoryKiB,
		argonHash.parallelism,
		uint32(len(argonHash.derivedKey)),
	)

	return subtle.ConstantTimeCompare(candidateHash, argonHash.derivedKey) == 1
}

func NeedsRehash(string) bool {
	return false
}
