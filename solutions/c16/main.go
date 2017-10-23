package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
	"net/url"
	"os"
	"time"

	"github.com/kyokomi/emoji"

	"github.com/logrusorgru/aurora"

	"github.com/pkg/errors"

	"github.com/hayeah/go-cryptopals"
)

var cbc *cryptopals.AES_CBC

func init() {
	var err error

	var key [16]byte
	var iv [16]byte

	_, err = io.ReadFull(rand.Reader, key[:])
	if err != nil {
		log.Fatalln("rand", err)
	}
	_, err = io.ReadFull(rand.Reader, iv[:])
	if err != nil {
		log.Fatalln("rand", err)
	}

	cbc, err = cryptopals.NewAES_CBC(key[:], iv[:])
	if err != nil {
		log.Fatalln("AES CBC", err)
	}
}

func modifyCipher(target string) (ctext []byte, err error) {
	bsize := 16

	if len(target) > bsize {
		return nil, errors.New("target cannot be larger than block size")
	}

	data := make([]byte, bsize*3)
	for i := range data {
		data[i] = 'a'
	}

	// xor a padding block with diff should change it to target string
	diff := make([]byte, bsize)
	targetBlockText := cryptopals.PadBytesLeft([]byte(target), 'a', bsize)
	cryptopals.XOR(diff, data[0:bsize], targetBlockText)

	var ctextW bytes.Buffer

	for i := 1; i <= len(data); i++ {
		// userdata=[PADDING] [TARGETBLOCK]
		// <     2 blocks   > < 1 block   >
		userdata := string(data[0 : i+bsize])
		emoji.Printf(":mag: %s len=%d %s\n", aurora.Cyan("Try userdata"), len(userdata), userdata)

		ctextW.Reset()
		err := encodeUserData(&ctextW, userdata)
		if err != nil {
			return nil, errors.Wrap(err, "encode user data")
		}

		ctext := ctextW.Bytes()

		// try to flip each block
		for i := 0; i < len(ctext)-bsize; i += bsize {
			b1 := ctext[i : i+bsize]
			cryptopals.XOR(b1, b1, diff)

			admin, err := isAdmin(bytes.NewReader(ctext))

			if err != nil {
				return nil, err
			}

			if admin {
				return ctext, nil
			}

			// failed. flip the block back
			cryptopals.XOR(b1, b1, diff)
		}
	}

	return nil, errors.New("failed to modify cipher text")
}

func main() {
	ctext, err := modifyCipher(";admin=true;")
	if err != nil {
		log.Fatalln("main", err)
	}

	emoji.Println(":star:", aurora.Green("Found modified ctext!"))

	// fmt.Println(aurora.Magenta("modified ctext:"))

	hexW := hex.Dumper(os.Stdout)
	defer hexW.Close()

	io.Copy(hexW, bytes.NewReader(ctext))

	// cryptopals.HexFormatCopy(os.Stdout, bytes.NewReader(ctext), 16)
}

func encodeUserData(w io.Writer, userdata string) error {
	now := time.Now()
	mrand.Seed(int64(now.Nanosecond()))

	size, err := rand.Int(rand.Reader, big.NewInt(10))
	if err != nil {
		return err
	}

	randprefix := make([]byte, size.Int64()+5)

	_, err = io.ReadFull(rand.Reader, randprefix)
	if err != nil {
		return err
	}

	ptext := string(randprefix) + "comment1=cooking%20MCs;userdata=" + url.QueryEscape(userdata) + ";comment2=%20like%20a%20pound%20of%20bacon"
	return cbc.Encrypt(w, bytes.NewReader([]byte(ptext)))
}

var isAdminDecryptW bytes.Buffer

func isAdmin(ctextR io.Reader) (bool, error) {
	isAdminDecryptW.Reset()
	err := cbc.Decrypt(&isAdminDecryptW, ctextR)
	if err != nil {
		return false, err
	}

	ptext := isAdminDecryptW.Bytes()
	fmt.Printf("   Check admin %#v\n", string(ptext))
	return bytes.Contains(ptext, []byte(";admin=true;")), nil
}
