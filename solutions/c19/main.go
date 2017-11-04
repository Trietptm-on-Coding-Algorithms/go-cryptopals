package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/hayeah/go-cryptopals"
	"github.com/pkg/errors"
)

const data = `SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==
Q29taW5nIHdpdGggdml2aWQgZmFjZXM=
RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==
RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=
SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk
T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=
UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=
T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl
VG8gcGxlYXNlIGEgY29tcGFuaW9u
QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==
QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=
QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==
QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==
SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==
SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==
VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==
V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==
V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==
U2hlIHJvZGUgdG8gaGFycmllcnM/
VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=
QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=
VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=
V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=
SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==
U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==
U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=
VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==
QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu
SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=
VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs
WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=
SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0
SW4gdGhlIGNhc3VhbCBjb21lZHk7
SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=
VHJhbnNmb3JtZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=`

func DecodeBase64Lines(data string) ([][]byte, error) {
	lines := strings.Split(data, "\n")

	var chunks [][]byte
	for _, line := range lines {
		chunk, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			return nil, err
		}

		chunks = append(chunks, chunk)
	}

	return chunks, nil
}

var key [16]byte
var iv [8]byte

func init() {
	// _, err := io.ReadFull(rand.Reader, key[:])
	// if err != nil {
	// 	log.Fatalln("rand key", err)
	// }
}

func do() error {
	ptexts, err := DecodeBase64Lines(data)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return err
	}

	var ctexts [][]byte

	for _, ptext := range ptexts {
		ctr := cryptopals.NewCTR(block, iv[:])
		r := cipher.StreamReader{S: ctr, R: bytes.NewReader(ptext)}
		ctext, err := ioutil.ReadAll(r)
		if err != nil {
			return errors.Wrap(err, "encrypt")
		}

		ctexts = append(ctexts, ctext)
	}

	// for i, ctext := range ctexts {
	// 	spew.Dump(i, ctext)
	// }

	err = analysis(ctexts)
	if err != nil {
		return err
	}

	return nil
}

type analyzer struct {
	ctexts [][]byte
	dtexts [][]byte

	keystream []byte
	dbuf      []byte

	oldbytes []byte
}

func newAnalyzer(ctexts [][]byte) *analyzer {
	maxLen := 0
	for _, ctext := range ctexts {
		if len(ctext) > maxLen {
			maxLen = len(ctext)
		}
	}

	dtexts := make([][]byte, len(ctexts))

	for i := range ctexts {
		dtexts[i] = make([]byte, len(ctexts[i]))
	}

	return &analyzer{
		ctexts: ctexts,
		dtexts: dtexts, // store all decrypted texts for statistical analysis

		keystream: make([]byte, maxLen),
		dbuf:      make([]byte, maxLen),
		oldbytes:  make([]byte, maxLen),
	}
}

func (a *analyzer) testGuess(i, pos int, data []byte) int {
	keybuf := a.keystream[pos : pos+len(data)]
	// save modifications to keystream
	old := a.oldbytes[:len(data)]
	copy(old, keybuf)

	a.guess(i, pos, data)

	// a.testDecrypt()
	score := a.score()

	// restore keystream
	copy(keybuf, old)

	return score
}

func (a *analyzer) guess(i, pos int, data []byte) {
	ctext := a.ctexts[i]

	cbuf := ctext[pos : pos+len(data)]
	keybuf := a.keystream[pos : pos+len(data)]

	for i := 0; i < len(data); i++ {
		keybuf[i] = cbuf[i] ^ data[i]
	}

	// decrypt everything with guessed keystream
	for i, ctext := range a.ctexts {
		buf := a.dtexts[i]
		cryptopals.XOR(buf, ctext, a.keystream)
		// dbytes[n] = ctext[0] ^ byte(i)
	}
}

func (a *analyzer) printDtexts() {
	fmt.Printf("keystream: %x\n", a.keystream)
	for i, dtext := range a.dtexts {
		fmt.Printf("%02x %#v\n", i, string(dtext))
		spew.Dump(dtext)
	}
}

func (a *analyzer) score() int {
	// count trigrams
	var trigramCounts int
	for _, trigram := range trigrams {
		for _, dtext := range a.dtexts {
			trigramCounts += bytes.Count(dtext, []byte(trigram))
		}
	}

	return trigramCounts
}

func analysis(ctexts [][]byte) error {

	a := newAnalyzer(ctexts)

	var test struct {
		i     int
		j     int
		guess []byte
		score int
	}

	for _, tri := range trigrams {
		guess := []byte(tri)

		for i := 0; i < len(ctexts); i++ {
			ctext := ctexts[0]

			for j := 0; j < len(ctext)-len(guess); j++ {
				score := a.testGuess(i, j, guess)
				if score > test.score {
					test.i = i
					test.j = j
					test.score = score
					test.guess = guess
				}
			}
		}

		a.guess(test.i, test.j, test.guess)
	}

	// a few manual guesses
	a.printDtexts()
	a.guess(0, 5, []byte("e"))
	a.guess(0x26, 0x12, []byte("y"))
	a.guess(0x14, 0x13, []byte("et"))
	a.guess(0x15, 0x15, []byte("ful"))

	a.printDtexts()

	return nil
}

func main() {
	err := do()
	if err != nil {
		log.Fatalln(err)
	}
}
