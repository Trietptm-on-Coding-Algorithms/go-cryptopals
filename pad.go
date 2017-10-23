package cryptopals

func PadBytesLeft(buf []byte, padbyte byte, size int) []byte {
	if len(buf) >= size {
		return buf
	}

	npad := size - len(buf)
	out := make([]byte, npad)

	return append(buf, out...)
}
