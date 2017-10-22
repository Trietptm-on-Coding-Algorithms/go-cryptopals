package main

import (
	"encoding/base64"
	"log"
	"os"

	"github.com/hayeah/go-cryptopals"
)

// XOR each byte of two slices into dst slice.

func main() {
	key := []byte("YELLOW SUBMARINE")
	var iv [16]byte

	cbc, err := cryptopals.NewAES_CBC(key, iv[:])
	if err != nil {
		log.Fatalln(err)
	}

	f, err := os.Open("10.txt")
	if err != nil {
		log.Fatalln("input file:", err)
	}
	defer f.Close()

	b64d := base64.NewDecoder(base64.StdEncoding, f)

	err = cbc.Decrypt(os.Stdout, b64d)
	if err != nil {
		log.Fatalln("decrypt:", err)
	}
}
