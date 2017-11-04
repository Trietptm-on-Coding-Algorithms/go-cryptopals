package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/hayeah/go-cryptopals"
)

const input = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="

func do() error {
	// inputR := base64.NewDecoder(base64.StdEncoding, bytes.NewReader([]byte(input))

	ctext, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return err
	}

	var iv [8]byte
	var key = []byte("YELLOW SUBMARINE")

	block, err := aes.NewCipher(key)

	s := cryptopals.NewCTR(block, iv[:])
	er := cipher.StreamReader{
		S: s,
		R: bytes.NewReader([]byte(ctext)),
	}

	fmt.Println("ptext:")
	io.Copy(os.Stdout, er)

	return nil
}

func main() {
	err := do()
	if err != nil {
		log.Fatalln(err)
	}
}
