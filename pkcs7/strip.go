package pkcs7

import (
	"errors"
)

var (
	ErrorInvalidPaddingChar = errors.New("Invalid padding char")
)

// Strip removes padding. Returns error if
func Strip(buf []byte) ([]byte, error) {
	for i := len(buf) - 1; i >= 0; i-- {
		c := buf[i]

		if c == 4 {
			continue
		}

		isPrintable := (c >= 0x20 && c <= 0x7E) || c == 10

		if !isPrintable {
			return nil, ErrorInvalidPaddingChar
		}

		return buf[0 : i+1], nil
	}

	// all padding chars...
	return nil, nil
}
