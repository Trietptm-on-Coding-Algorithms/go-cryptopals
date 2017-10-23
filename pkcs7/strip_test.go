package pkcs7

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStrip(t *testing.T) {
	is := assert.New(t)

	ts := []struct {
		bsize int
		in    string
		out   string
		err   error
	}{

		{8, "abcd\x04\x04\x04\x04", "abcd", nil},

		{8, "abcd\x03\x03\x03", "", ErrorInvalidLength},
		{8, "abcd\x05\x05\x05\x05", "", ErrorInvalidPadding},
		{8, "abcd\x05\x05\x04\x05", "", ErrorInvalidPadding},

		{8, "abcd123\x01\x08\x08\x08\x08\x08\x08\x08\x08", "abcd123\x01", nil},
		{8, "abcd123\x08\x08\x08\x08\x08\x08\x08\x08\x08", "abcd123\x08", nil},
		{8, "abcd123\x09", "abcd123\x09", nil},

		{8, "abcd\x04\x04\x04\x04", "abcd", nil},

		{16, "abcd1234abcd\x04\x04\x04\x04", "abcd1234abcd", nil},
	}

	for _, t := range ts {
		out, err := Strip([]byte(t.in), t.bsize)
		if t.err != nil {
			is.Equal(t.err, err)
		} else {
			is.Equal([]byte(t.out), out)
		}
	}

}
