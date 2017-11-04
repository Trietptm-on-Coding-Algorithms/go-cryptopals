package main

import "fmt"
import "github.com/hayeah/go-cryptopals/random"

func main() {
	mt := random.NewMersenneTwister()
	mt.Seed(1)

	for i := 0; i < 20; i++ {
		fmt.Printf("%03d %d\n", i, mt.Next())
	}
}
