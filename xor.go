package cryptopals

func XOR(dst, data, key []byte) {
	for i := 0; i < len(data); i++ {
		dst[i] = data[i] ^ key[i%len(key)]
	}
}
