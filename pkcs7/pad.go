package pkcs7

import (
	"io"
)

type PaddedReader struct {
	bsize int
	r     io.Reader

	lastByteRead byte
	bytesRead    int

	npad    int
	padByte byte
	eofed   bool
}

func NewPaddedReader(r io.Reader, bsize int) *PaddedReader {
	return &PaddedReader{r: r, bsize: bsize}
}

func (r *PaddedReader) Read(p []byte) (int, error) {
	nread, err := r.r.Read(p)

	if nread > 0 {
		r.bytesRead += nread
		r.lastByteRead = p[nread-1]
		return nread, nil
	}

	if err == io.EOF {
		if !r.eofed {
			r.eofed = true

			if r.bytesRead%r.bsize != 0 {
				// last block does not align with block size
				r.npad = r.bsize - r.bytesRead%r.bsize
			} else {
				// pad with a whole block
				r.npad = r.bsize

				// last block DOES align with block size. Check if last byte is ambiguous
				// if int(r.lastByteRead) <= r.bsize {
				// 	// lastByte is ambiguous, append an extra padding block
				// 	r.npad = r.bsize
				// } else {
				// 	r.npad = 0
				// }
			}

			r.padByte = byte(r.npad)

		}

		if r.npad == 0 {
			return 0, io.EOF
		}

		npad := r.npad
		if npad > len(p) {
			npad = len(p)
		}

		for i := 0; i < npad; i++ {
			p[i] = r.padByte
		}

		r.npad -= npad
		return npad, nil
	}

	return nread, err
}

// Pad copies content from src to writer, writing padding bytes if necessary.
func Pad(p []byte, bsize int) []byte {
	if len(p) > bsize {
		panic("given block is longer than block size")
	}

	if len(p) == bsize {
		lastByte := p[len(p)-1]
		if int(lastByte) > bsize {
			return p
		}

		// last byte is potentially ambiguous as padding char. Add an extra padding block.
		out := make([]byte, bsize*2)
		copy(out, p)
		for i := bsize; i < bsize*2; i++ {
			out[i] = byte(bsize)
		}

		return out
	}

	npad := bsize - len(p)
	out := make([]byte, len(p)+npad)
	copy(out, p)

	for i := len(p); i < bsize; i++ {
		out[i] = byte(npad)
	}
	return out
}
