package cryptopals

import (
	"bytes"
	"testing"

	"github.com/hayeah/go-cryptopals/pkcs7"

	"github.com/stretchr/testify/assert"
)

const zarathustra = `When Zarathustra was thirty years old, he left his home and the lake of his home, and went into the mountains. There he enjoyed his spirit and his solitude, and for ten years did not weary of it. But at last his heart changed, and rising one morning with the rosy dawn, he went before the sun`

func TestCBC(t *testing.T) {
	is := assert.New(t)

	key := []byte("abcd1234abcd1234")
	iv := []byte("wxyz9876wxyz9876")

	cbc, err := NewAES_CBC(key, iv)
	is.NoError(err)

	var w bytes.Buffer
	err = cbc.Encrypt(&w, bytes.NewReader([]byte(zarathustra)))
	is.NoError(err)

	ctext := make([]byte, w.Len())
	copy(ctext, w.Bytes())

	w.Reset()
	cbc.Decrypt(&w, bytes.NewReader(ctext))
	ptext := w.Bytes()
	ptext, err = pkcs7.Strip(ptext)
	is.NoError(err)
	is.Equal(zarathustra, string(ptext))
}
