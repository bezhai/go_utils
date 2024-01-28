package authx

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
)

func GenerateToken(salt string, body string, secret string) string {
	data := salt + body + secret
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func GenSalt(n int) (string, error) {
	const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	bytes := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", err
	}
	for i, b := range bytes {
		bytes[i] = letters[b%byte(len(letters))]
	}
	return string(bytes), nil
}
