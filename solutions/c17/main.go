package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	mrand "math/rand"
	"time"

	"github.com/hayeah/go-cryptopals/pkcs7"
	"github.com/kyokomi/emoji"
	"github.com/logrusorgru/aurora"

	"github.com/hayeah/go-cryptopals"

	"github.com/pkg/errors"
)

var secret = `MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93`

const clearLine = "\033[2K\033[1000D"

var cbc *cryptopals.AES_CBC

var key [16]byte
var iv [16]byte

func init() {
	_, err := rand.Read(key[:])
	if err != nil {
		log.Fatalln("gen key", err)
	}

	_, err = rand.Read(iv[:])
	if err != nil {
		log.Fatalln("gen iv", err)
	}

	cbc, err = cryptopals.NewAES_CBC(key[:], iv[:])
	if err != nil {
		log.Fatalln("AES CBC:", err)
	}
}

func randomPtext() ([]byte, error) {
	s := bufio.NewScanner(bytes.NewReader([]byte(secret)))
	s.Split(bufio.ScanLines)

	var lines [][]byte
	for s.Scan() {
		line := s.Bytes()
		lines = append(lines, line)
	}
	err := s.Err()
	if err != nil {
		return nil, err
	}

	// spew.Dump("lines", lines)
	now := time.Now()
	mrand.Seed(int64(now.Nanosecond()))
	n := mrand.Intn(len(lines))
	// n := 0
	line := lines[n]
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(line)))
	_, err = base64.StdEncoding.Decode(dst, line)
	if err != nil {
		return nil, err
	}

	return dst, nil
}

type cbcPaddingOracleCracker struct {
	// initial vector is known
	IV    []byte
	Ctext []byte

	Bsize int

	// decryption buffer
	dbuf bytes.Buffer
}

var errorSearchExhausted = errors.New("search exhausted")

func (c *cbcPaddingOracleCracker) analyzeBlock(guesses, ctext, blockPrev, block []byte, i int) error {
	// i is the nth char from the end. 0 is the last char.

	target := byte(i + 1)

	// the byte in block we want to edit
	n := c.Bsize - 1 - i

	// before returning, restore the cipher text
	octextBytes := make([]byte, i+1)
	copy(octextBytes, blockPrev[n:c.Bsize])

	defer func() {
		copy(blockPrev[n:c.Bsize], octextBytes)
	}()

	for j := 0; j <= 0xff; j++ {
		copy(blockPrev[n:c.Bsize], octextBytes)
		blockPrev[n] = octextBytes[0]

		// Fiddle with the nth byte, if valid padding, recurse.
		// j is the guess byte
		guess := byte(j)
		edit := guess ^ target
		blockPrev[n] ^= edit

		guesses[n] = guess
		// fmt.Printf("guess: %02d %#v", i, string(guesses))

		// need to recover blockPrev to original ctext, then attempt to modify each byte to target, by assuming the bytes in "guesses"
		for ii := 0; ii < i; ii++ {
			n := c.Bsize - 1 - ii
			guess := guesses[n]
			edit := guess ^ target
			// if i == 1 {
			// 	fmt.Println("n guess edit", n, guess, edit)
			// }
			blockPrev[n] ^= edit
		}

		valid, err := c.validPadding(ctext)

		if err != nil {
			return err
		}

		if !valid {
			// guess next char
			continue
		}

		guesses[n] = guess

		if i == c.Bsize-1 {
			// done, recursion bottom
			return nil
		}

		copy(blockPrev[n:c.Bsize], octextBytes)
		err = c.analyzeBlock(guesses, ctext, blockPrev, block, i+1)
		if err == nil {
			return nil
		}

		// recursion has error, try next guess
	}

	// if in recursion, parent call will retry with another guess
	return errorSearchExhausted
}

func (c *cbcPaddingOracleCracker) run() ([]byte, error) {

	bsize := c.Bsize
	ctext := c.Ctext

	guesses := make([]byte, bsize)

	var output []byte

	for i := 0; i < len(ctext)/bsize; i++ {
		block := ctext[i*bsize : (i+1)*bsize]
		var blockPrev []byte
		if i == 0 {
			blockPrev = c.IV
		} else {
			blockPrev = ctext[(i-1)*bsize : i*bsize]
		}

		err := c.analyzeBlock(guesses, ctext[:(i+1)*bsize], blockPrev, block, 0)
		if err != nil {
			return nil, err
		}

		output = append(output, guesses...)

		fmt.Printf("block[%02d]: %#v\n", i, string(guesses))
	}

	return pkcs7.Strip(output, bsize)
}

func (c *cbcPaddingOracleCracker) validPadding(ctext []byte) (bool, error) {
	c.dbuf.Reset()

	err := cbc.Decrypt(&c.dbuf, bytes.NewReader(ctext))
	if err != nil {
		return false, errors.Wrap(err, "cbc decrypt")
	}

	// spew.Dump(c.dbuf.Bytes())

	_, err = pkcs7.Strip(c.dbuf.Bytes(), c.Bsize)
	if err != nil {
		return false, nil
	}

	return true, nil
}

func testRun() error {
	bsize := 16

	ptext, err := randomPtext()
	if err != nil {
		return errors.Wrap(err, "random ptext")
	}

	fmt.Printf("ptext = %#v\n", string(ptext))

	var ebuf bytes.Buffer
	err = cbc.Encrypt(&ebuf, bytes.NewReader(ptext))
	if err != nil {
		return errors.Wrap(err, "cbc encrypt")
	}

	//

	ctext := ebuf.Bytes()
	cracker := cbcPaddingOracleCracker{
		IV:    iv[:],
		Ctext: ctext,
		Bsize: bsize,
	}

	output, err := cracker.run()
	if err != nil {
		return errors.Wrap(err, "crack cbc")
	}

	emoji.Println(":star:", aurora.Green("Padding oracle attack success!"))
	fmt.Printf("%#v\n", string(output))

	return nil
}

func main() {
	err := testRun()
	if err != nil {
		log.Fatalln(err)
	}
}
