package main

import (
	"fmt"
	"testing"

	"github.com/hayeah/go-cryptopals"

	"github.com/stretchr/testify/assert"
)

func TestEncodeUserData(t *testing.T) {
	is := assert.New(t)
	is.Equal(
		"comment1=cooking%20MCs;userdata=%3B%3D%3B%3D;comment2=%20like%20a%20pound%20of%20bacon",
		encodeUserData(";=;="),
	)
}

func TestDiff(t *testing.T) {
	target := []byte("johnny")
	from := []byte("abcd[]")

	diff := make([]byte, len(target))
	target2 := make([]byte, len(target))

	cryptopals.XOR(diff, target, from)

	fmt.Println("diff", diff)

	cryptopals.XOR(target2, diff, from)

	fmt.Println("target2", string(target2))

}
