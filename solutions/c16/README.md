# find the edit block

```
ptext = decrypt ctext = aes_ecb_decrypt(ctext) ^ ctext_prev
```

We can edit the ptext however we want by editing `ctext_prev`

```
ptext = decrypt ctext = aes_ecb_decrypt(ctext) ^ ctext_prev ^ edit
```

To change ptext block to what we want, just xor its expected plaintext with the target:

```
edit ^ block = target
edit = block ^ target
```

# pad, align, flip

< userdata=[PAD] > + < [PAD * bsize] > + < [padleft(target string)] >

* assume that the oracle function only scans for string the 'admin=true' string.
  * bit-flipping will garble URL encoding

* loop extend padding, for alignment. up to bsize * 2
  * loop through each block
    * try flipping the block, and see if next block comes out right
    * if not, reset flipped block, and try next block
