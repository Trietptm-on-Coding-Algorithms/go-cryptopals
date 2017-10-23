package cryptopals

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"

	"github.com/hayeah/go-cryptopals/pkcs7"
)

var (
	ErrorIVNotBlockSize = errors.New("IV is not the same as key size")
)

// encrypt ptext = aes_ecb_encrypt(ptext ^ ctext_prev)

type AES_CBC struct {
	cb    cipher.Block
	iv    []byte
	bsize int
}

func NewAES_CBC(key, iv []byte) (*AES_CBC, error) {
	cb, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	bsize := len(key)
	if len(iv) != bsize {
		return nil, ErrorIVNotBlockSize
	}

	return &AES_CBC{
		cb:    cb,
		iv:    iv,
		bsize: bsize,
	}, nil
}

// ctext = encrypt ptext = aes_ecb_encrypt(ptext ^ ctext_prev)
// ptext = decrypt ctext = aes_ecb_decrypt(ctext) ^ ctext_prev
func (c *AES_CBC) Encrypt(w io.Writer, r io.Reader) error {
	r = pkcs7.NewPaddedReader(r, c.bsize)

	ptext := make([]byte, c.bsize)
	obuf := make([]byte, c.bsize)

	ctextPrev := make([]byte, c.bsize)
	copy(ctextPrev, c.iv)

	for {
		_, err := io.ReadFull(r, ptext)

		if err != nil {
			switch err {
			case io.EOF:
				return nil
			case io.ErrUnexpectedEOF:
				panic("pkcs7.NewPaddedReader should always be able to return full blocks")
			case err:
				return err
			}
		}

		XOR(ptext, ptext, ctextPrev)
		c.cb.Encrypt(obuf, ptext)
		copy(ctextPrev, obuf)

		_, werr := w.Write(obuf)
		if werr != nil {
			return werr
		}
	}
}

// ctext = encrypt ptext = aes_ecb_encrypt(ptext ^ ctext_prev)
// ptext = decrypt ctext = aes_ecb_decrypt(ctext) ^ ctext_prev
func (c *AES_CBC) Decrypt(w io.Writer, r io.Reader) error {
	ctext := make([]byte, c.bsize)
	obuf := make([]byte, c.bsize)

	ctextPrev := make([]byte, c.bsize)
	copy(ctextPrev, c.iv)

	for {
		_, err := io.ReadFull(r, ctext)

		if err == io.EOF {
			return nil
		}

		if err != nil {
			return err
		}

		c.cb.Decrypt(obuf, ctext)
		XOR(obuf, obuf, ctextPrev)
		copy(ctextPrev, ctext)

		_, err = w.Write(obuf)
		if err != nil {
			return err
		}

	}
}
