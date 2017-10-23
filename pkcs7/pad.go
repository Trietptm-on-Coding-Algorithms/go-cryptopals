package pkcs7

// PadWrite copies content from src to writer, writing padding bytes if necessary.
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
