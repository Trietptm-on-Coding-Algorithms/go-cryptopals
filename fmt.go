package cryptopals

import (
	"fmt"
	"io"
)

func HexFormatCopy(w io.Writer, r io.Reader, bsize uint) (err error) {
	ibuf := make([]byte, bsize)

	n := 0
	for {
		nread, err := r.Read(ibuf[:])
		if nread > 0 {

			_, werr := fmt.Fprintf(w, "%04d: %x\n", n, ibuf)
			if werr != nil {
				return werr
			}
			n += nread
		}

		if err == io.EOF {
			return nil
		}

		if err != nil {
			return err
		}
	}
}
