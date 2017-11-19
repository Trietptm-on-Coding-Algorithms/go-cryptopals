package cryptopals

import (
	"crypto/aes"
	"testing"

	"github.com/stretchr/testify/require"
)

const bsize = 16

func TestCTRSeek(tt *testing.T) {

	is := require.New(tt)

	var key [bsize]byte
	var iv [bsize / 2]byte

	block, err := aes.NewCipher(key[:])
	is.NoError(err)

	s := NewCTR(block, iv[:])

	ptext := []byte("abcd1234efgh5678qwerasdftyuighjk")
	ctext := make([]byte, len(ptext))
	s.XORKeyStream(ctext, ptext)

	// s.Seek(0)
	// spew.Dump("ks block 0", s.keystream)

	// s.Seek(1)
	// spew.Dump("ks block 0", s.keystream)

	// s.Seek(16)
	// spew.Dump("ks block 1", s.keystream)

	buf := make([]byte, bsize)
	for i := 0; i < bsize; i++ {
		s.Seek(i)
		s.XORKeyStream(buf, ptext[i:i+16])
		is.Equal(ctext[i:i+16], buf, "seek %d", i)
	}
}
