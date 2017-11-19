package main

import (
	"fmt"
	"math"
	"testing"

	"github.com/hayeah/go-cryptopals"

	"github.com/stretchr/testify/require"
)

func TestCrack(tt *testing.T) {
	is := require.New(tt)

	for i := 0; i < 10; i++ {
		n, err := cryptopals.CryptoRandInt()
		is.NoError(err)

		key := n % math.MaxUint16

		o := &Oracle{
			key: key,
		}

		crackedKey, err := CrackOracle(o)
		is.NoError(err)

		fmt.Println("cracked key", crackedKey)
		is.Equal(key, crackedKey)
	}
}
