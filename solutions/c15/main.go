package main

import (
	"fmt"
	"log"

	"github.com/hayeah/go-cryptopals/pkcs7"
)

func main() {
	r, err := pkcs7.Strip([]byte("ICE ICE BABY\x04\x04\x04\x04"))

	if err != nil {
		log.Fatalln(err)
	}

	fmt.Printf("Stripped: %#v\n", string(r))

	// fmt.Println("stripped: ", string(r))
}
