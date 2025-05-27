package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"strings"
)

const (
	encryptPrefix  = "$e$3$"
	encryptKeySize = 32
	alignment      = 128
)

var (
	// WARNING! Change these seeds for production deployments!
	seed1 uint64 = 17384293841293847123
	seed2 uint64 = 3022513517701228024
	// make build SEED=random
	// or sha256 derived from a string:
	// make build SEED=aCustomString
	// or fixed seeds:
	// make build SEED1=17384293841293847123 SEED2=3022513517701228024

	ErrInvalidData = errors.New("invalid data")
)

type Cipher struct {
	aead cipher.AEAD
}

func New() *Cipher {
	pcg := rand.NewPCG(seed1, seed2)
	buf := make([]byte, 32)
	for i := 0; i < 32; i += 8 {
		binary.LittleEndian.PutUint64(buf[i:], pcg.Uint64())
	}

	// Error always nil for these functions
	salt     := sha256.Sum256([]byte(buf))
	key, _   := hkdf.Key(sha256.New, buf, salt[:], base64.RawStdEncoding.EncodeToString(buf), encryptKeySize)
	block, _ := aes.NewCipher(key)
	aead, _  := cipher.NewGCMWithRandomNonce(block)
	return &Cipher{ aead: aead }
}

func (c *Cipher) Encrypt(plainText string) string {
    data := []byte(plainText)

    dataLen  := len(data)
    totalLen := 2 + dataLen
    padLen   := (alignment - (totalLen % alignment)) % alignment
    padded   := make([]byte, totalLen + padLen)

    binary.BigEndian.PutUint16(padded, uint16(dataLen))
    copy(padded[2:], data)

    cipherText := c.aead.Seal(nil, nil, padded, nil)
    return encryptPrefix + base64.RawStdEncoding.EncodeToString(cipherText)
}

func (c *Cipher) Decrypt(cipherText string) (string, error) {
    if !c.IsEncrypted(cipherText) {
        return cipherText, nil
    }

	data, err := base64.RawStdEncoding.DecodeString(cipherText[len(encryptPrefix):])
    if err != nil {
        return "", err
    }

    plain, err := c.aead.Open(nil, nil, data, nil)
    if err != nil {
        return "", err
    }

    if len(plain) < 2 {
        return "", ErrInvalidData
    }

    msgLen := binary.BigEndian.Uint16(plain)

    if int(msgLen) > len(plain) - 2 {
        return "", ErrInvalidData
    }
    return string(plain[2:2 + msgLen]), nil
}

func (c *Cipher) IsEncrypted(s string) bool {
	return strings.HasPrefix(s, encryptPrefix)
}
