+ assume the "seek' function from c25 does not exist, otherwise it's probably trivial.

"comment1=cooking%20MCs;userdata=" + chosentext + ";comment2=%20like%20a%20pound%20of%20bacon"

+ suppose the target ptext to inject is:
  + ";admin=true;"
  + "aaaaaaaaaaaa" <- use this as the chosen text
  + diff the cipher text with the chosen text to get the key stream for that position
  + ctext ^ edit = target
  + edit = ctext ^ target

* choosing a location in cipher text to bitflip
  * the chosen text should be a long "aaaaaa...aaaaaa" string
  * just arbitrarily flip the middle of the cipher text, assuming that it IS "aaa...aaa"
  * this would work with random prefix as well

* can refine algorithm slightly by trying to find a shorter chosen text
  * start from shorter chosen text, and increase the length until success
