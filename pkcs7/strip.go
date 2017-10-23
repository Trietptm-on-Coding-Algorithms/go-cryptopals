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

	npad := int(p[len(p)-1])
	if npad > bsize {
		return p, nil
	}

	for i := 0; i < npad; i++ {
		if p[len(p)-1-i] != byte(npad) {
			return nil, ErrorInvalidPadding
		}
	}

	return p[:len(p)-npad], nil
}
