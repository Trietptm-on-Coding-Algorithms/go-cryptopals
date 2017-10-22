package cryptopals

func XOR(dst, str, key []byte) {
	for i := 0; i < len(str); i++ {
		dst[i] = str[i] ^ key[i%len(key)]
	}
}
