package main

import (
	"crypto/aes"
	"encoding/base64"
	"log"
	"os"

	"github.com/hayeah/go-cryptopals"
)

func do() (err error) {
	f, err := os.Open("7.txt")
	if err != nil {
		return
	}
	defer f.Close()

	r := base64.NewDecoder(base64.StdEncoding, f)

	key := []byte("YELLOW SUBMARINE")
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	ecb := cryptopals.ECB{Block: block}

	err = ecb.Decrypt(r, os.Stdout)
	if err != nil {
		return
	}

	return
}

func main() {
	err := do()
	if err != nil {
		log.Fatalln(err)
	}
}
