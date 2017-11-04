package cryptopals

import (
	"crypto/cipher"
	"encoding/binary"
)

// mimic golang's standard API

// ctrStream turns a block cipher into CTR mode stream
type ctrStream struct {
	cipher cipher.Block

	// This implementation differs from NIST Special Publication 800-38A. In which the nonce is assumed to be sufficiently random, and combeind with counter.
	counter uint64

	unreadKeybytes int
	keystream      [16]byte

	// [ iv (8 bytes) ][ counter (8 bytes) ]
	xorbuf [16]byte
}

// XORKeyStream implements cipher.Stream interface
func (s *ctrStream) XORKeyStream(dst, src []byte) {
	n := len(dst)

	bsize := s.cipher.BlockSize()

	for i := 0; i < n; i++ {
		if s.unreadKeybytes == 0 {
			// write counter to the lower 8 bytes
			binary.LittleEndian.PutUint64(s.xorbuf[8:], uint64(s.counter))

			// calculate the next block of keystream
			s.cipher.Encrypt(s.keystream[:], s.xorbuf[:])

			s.counter++
			s.unreadKeybytes = 16
		}

		keybyte := s.keystream[bsize-s.unreadKeybytes]
		dst[i] = src[i] ^ keybyte
		s.unreadKeybytes--
	}
}

func NewCTR(block cipher.Block, iv []byte) cipher.Stream {
	// assume 16 bytes block size...
	if len(iv) != 8 {
		panic("iv should be 8 bytes")
	}

	// bsize := block.BlockSize()

	s := &ctrStream{
		cipher: block,
		// keystream: make([]byte, bsize),
	}

	// copy 8 bytes from iv to the upper 8 bytes of xorbuf
	copy(s.xorbuf[:8], iv)

	return s
}

// https://golang.org/pkg/crypto/cipher/#Stream

/*
er := ctr.EncryptStream(reader)
io.Copy(w, er)

dr := ctr.DecryptStream(reader)
io.Copy(w, dr)
*/
