package authx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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

// GenerateHMACKey 使用给定的密钥和盐生成新的 HMAC 密钥。
func GenerateHMACKey(key []byte, salt string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(salt))
	return h.Sum(nil)
}

// Encrypt 使用给定的密钥和盐加密文本。
func Encrypt(plaintext []byte, key []byte, salt string) ([]byte, error) {

	block, err := aes.NewCipher(GenerateHMACKey(key, salt))
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return []byte(base64.StdEncoding.EncodeToString(ciphertext)), nil
}

// Decrypt 使用给定的密钥和盐解密文本。
func Decrypt(cryptoText string, key []byte, salt string) ([]byte, error) {

	ciphertext, err := base64.StdEncoding.DecodeString(cryptoText)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(GenerateHMACKey(key, salt))
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, err
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}
