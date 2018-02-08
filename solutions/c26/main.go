package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"log"
	"net/url"

	"github.com/davecgh/go-spew/spew"

	cryptopals "github.com/hayeah/go-cryptopals"
)

// var ctr *cryptopals.CTRStream
var iv []byte
var block cipher.Block

func setup() (err error) {
	iv = make([]byte, 8)
	_, err = rand.Read(iv)
	if err != nil {
		return
	}

	key := make([]byte, 16)
	_, err = rand.Read(key)
	if err != nil {
		return
	}

	block, err = aes.NewCipher(key)
	if err != nil {
		return
	}

	return nil
}

type Oracle struct {
	iv    []byte
	block cipher.Block
}

func encodeUserData(userdata []byte) []byte {

	randPrefix, err := cryptopals.CryptoRandPrefix(16)
	if err != nil {
		log.Fatalln("err gen random prefix", err)
	}

	ctr := cryptopals.NewCTR(block, iv)

	ptext := string(randPrefix) + "comment1=cooking%20MCs;userdata=" + url.QueryEscape(string(userdata)) + ";comment2=%20like%20a%20pound%20of%20bacon"

	ctext := make([]byte, len(ptext))

	ctr.XORKeyStream(ctext, []byte(ptext))

	return ctext
}

func checkIsAdmin(ctext []byte, reveal bool) bool {
	ctr := cryptopals.NewCTR(block, iv)

	ptext := make([]byte, len(ctext))

	ctr.XORKeyStream(ptext, ctext)

	if reveal {
		spew.Dump("decoded ptext:", ptext)
	}

	return bytes.Contains(ptext, []byte(";admin=true;"))
}

// Attepmt to bitfip a cipher using length n chosen text
// returns nil if failed to crack
func crackN(target []byte, chosenTextLength int) []byte {
	// initialize a long chosentext of all 'a's
	chosenTextBuf := make([]byte, chosenTextLength)
	for i := range chosenTextBuf {
		chosenTextBuf[i] = 'a'
	}

	// chosenText ^ edit = target
	editBuf := make([]byte, len(target))
	cryptopals.XOR(editBuf, target, chosenTextBuf[0:len(target)])

	i := 0
	for {
		ctext := encodeUserData(chosenTextBuf)

		// chose a ctext range to edit. Just arbitrarily choose the 1/3 location
		from := len(ctext) / 3
		subctext := ctext[from : from+len(target)]

		// edit the cipher text, assuming that it is all 'a's
		cryptopals.XOR(subctext, subctext, editBuf)

		isAdmin := checkIsAdmin(ctext, false)

		if isAdmin {
			return ctext
		}

		// give up after 100 tries
		i++
		if i > 100 {
			return nil
		}
	}
}

// Bitflip a cipher text so the plain text has the string "admin=true"
func crack(target []byte) []byte {
	// estimate the size of the ctext. We want to use a chosen text that's
	// significantly larger than the ctext.
	ctext0 := encodeUserData([]byte("a"))

	i := len(target) + len(ctext0)
	for {
		fmt.Println("using chosen text of length:", i)

		ctext := crackN(target, i)
		if ctext != nil {
			return ctext
		}

		i++
	}
}

func main() {
	err := setup()
	if err != nil {
		log.Fatalln("setup", err)
	}

	ctext := crack([]byte(";admin=true;"))
	spew.Dump("cracked ctext:", ctext)

	checkIsAdmin(ctext, true)

}
