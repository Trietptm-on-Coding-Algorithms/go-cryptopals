package cryptopals

import (
	"crypto/cipher"
	"io"
)

type ECB struct {
	Block cipher.Block
}

func (e *ECB) Decrypt(r io.Reader, w io.Writer) error {
	buf := make([]byte, e.Block.BlockSize())

	for {
		_, err := io.ReadFull(r, buf)

		if err == io.EOF {
			return nil
		}

		if err != nil {
			return err
		}

		e.Block.Decrypt(buf, buf)

		_, err = w.Write(buf)
		if err != nil {
			return err
		}
	}

}
