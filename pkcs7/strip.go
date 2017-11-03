package pkcs7

import (
	"errors"
)

var (
	ErrorInvalidPadding = errors.New("Invalid padding")
	ErrorInvalidLength  = errors.New("Length not multiples of block size")
)

// Strip removes padding. Returns error if
func Strip(p []byte, bsize int) ([]byte, error) {
	if len(p)%bsize != 0 {
		return nil, ErrorInvalidLength
	}

	if len(p) == 0 {
		return nil, nil
	}

	npad := int(p[len(p)-1])

	// if npad > bsize {
	// 	// non-ambiguous byte
	// 	return p, nil
	// }

	for i := 1; i < int(npad); i++ {
		if byte(npad) != p[len(p)-1-i] {
			return nil, ErrorInvalidPadding
		}
	}

	return p[:len(p)-npad], nil
}
