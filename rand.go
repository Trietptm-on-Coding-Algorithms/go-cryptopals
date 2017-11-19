package cryptopals

import (
	"crypto/rand"
	"encoding/binary"
)

// CryptoRandInt returns a cryptographically secure uint64
func CryptoRandInt() (uint64, error) {
	var buf [8]byte

	_, err := rand.Read(buf[:])
	if err != nil {
		return 0, err
	}

	return binary.BigEndian.Uint64(buf[:]), nil
}

// CryptoRandPrefix returns a random prefix of at most n bytes
func CryptoRandPrefix(maxSize uint64) ([]byte, error) {
	n, err := CryptoRandInt()
	if err != nil {
		return nil, err
	}

	size := n % maxSize

	prefix := make([]byte, size)
	_, err = rand.Read(prefix)
	if err != nil {
		return nil, err
	}

	return prefix, nil
}
