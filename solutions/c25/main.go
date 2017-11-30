package main

import (
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/davecgh/go-spew/spew"
	"github.com/hayeah/go-cryptopals"
)

const bsize = 16

type Oracle struct {
	// cryptopals.
	s *cryptopals.CTRStream

	ctext []byte
	ptext []byte
}

func NewOracle(ptext []byte) (orc *Oracle, err error) {
	key := make([]byte, 16)
	iv := make([]byte, 8)

	_, err = rand.Read(key)
	if err != nil {
		return
	}

	_, err = rand.Read(iv)
	if err != nil {
		return
	}

	b, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	s := cryptopals.NewCTR(b, iv)

	ctext := make([]byte, len(ptext))
	s.XORKeyStream(ctext, ptext)

	return &Oracle{
		s:     s,
		ctext: ctext,
		ptext: ptext,
	}, nil
}

func (o *Oracle) Edit(offset int, newPtext []byte) {
	o.s.Seek(offset)
	o.s.XORKeyStream(o.ctext[offset:], newPtext)
}

var zeroBlock [bsize]byte

func Crack(o *Oracle) (output []byte, err error) {
	// used to store old cipher block
	oldCTextBlock := make([]byte, bsize)

	ctext := o.ctext

	output = make([]byte, len(ctext))

	for i := 0; i < len(ctext); i += bsize {
		ctextBlock := ctext[i : i+bsize]
		copy(oldCTextBlock, ctextBlock)
		o.Edit(i, zeroBlock[:])
		// now ctext should hold the key stream block. xor it with oldCTextBlock to get the plain text output

		cryptopals.XOR(output[i:i+bsize], ctextBlock, oldCTextBlock)
	}

	return output, nil
}

func Do() (err error) {
	f, err := os.Open("25.ptext.txt")
	if err != nil {
		return
	}
	defer f.Close()

	// r := base64.NewDecoder(base64.StdEncoding, f)

	ptext, err := ioutil.ReadAll(f)
	if err != nil {
		return
	}

	fmt.Println("len(ptext)", len(ptext))
	fmt.Println("ptext", string(ptext[:200]))

	o, err := NewOracle(ptext)
	if err != nil {
		return
	}

	output, err := Crack(o)
	if err != nil {
		return
	}

	spew.Dump(output)

	return nil
}

func main() {
	err := Do()
	if err != nil {
		log.Println(err)
	}
}
