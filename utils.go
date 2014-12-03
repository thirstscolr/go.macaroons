package macaroons

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

const (
	keyLength = 32
)

func deriveMacaroonKey(identifier string) []byte {
	// BUG(tdaniels): Hard coded master key used for mKey derivation.
	mKey := []byte("secret")
	derivedKey := signature(mKey, []byte(identifier))

	return derivedKey
}

func signature(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func newCaveatKey() (*[keyLength]byte, error) {
	var key [keyLength]byte
	_, err := rand.Reader.Read(key[:])
	if err != nil {
		return nil, err
	}

	return &key, nil
}

func encrypt(key, data []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// BUG(tdaniels): Static IV used for encryption
	iv := []byte("12345678901234567890123456789012")
	iv = iv[:aes.BlockSize]
	encrypter := cipher.NewCFBEncrypter(block, iv)
	ciphertext := make([]byte, len(data))
	encrypter.XORKeyStream(ciphertext, data)
	encrypted := base64.StdEncoding.EncodeToString(ciphertext)

	return encrypted, nil
}

func decrypt(key []byte, ciphertext string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := []byte("12345678901234567890123456789012")
	iv = iv[:aes.BlockSize]
	encrypter := cipher.NewCFBDecrypter(block, iv)

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(data))
	encrypter.XORKeyStream(plaintext, data)

	return plaintext, nil

}
