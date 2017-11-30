
* assume Oracle: `edit(ciphertext, key, offset, newtext)`.
* just pass in 0 byte as newtext. result will be keystream byte.
* having keystream byte, xor with ciphertext byte to get the plain text.

