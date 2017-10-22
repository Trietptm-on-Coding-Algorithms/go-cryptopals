package pkcs7

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStrip(t *testing.T) {
	is := assert.New(t)

	ts := []struct {
		in  string
		out string
		err error
	}{
		{"abc\x04\x04\x04", "abc", nil},
		{"abc\x04\x04\x05", "abc", ErrorInvalidPaddingChar},
		{"abc\x05\x04\x04", "abc", ErrorInvalidPaddingChar},
		{"ab\x04c\x04\x04", "ab\x04c", nil},
	}

	for _, t := range ts {
		out, err := Strip([]byte(t.in))
		if t.err != nil {
			is.Equal(t.err, err)
		} else {
			is.Equal([]byte(t.out), out)
		}
	}

}
