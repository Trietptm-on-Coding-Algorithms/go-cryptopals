* the challenge asks to break 16 bit seed. can i break 64bit seed?
  * no. too many possible seeds to try

* 2^16 is only 65536. can brute force easily

# solution

* i just need to look at the last 8 bytes, the find a seed that generates that number
  * the chosen ptext should just be zeroes
* need to be careful about the rand prefix's length not modulo 8
  * i could generate [8~15] bytes. check cipher text is modulo 8, then crack the last 8 bytes

Run:

```
go test -run TestCrack
```