package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/hayeah/go-cryptopals/random"
)

// const timeDay = time.Second * 3600

func crackSeed(n uint64) uint64 {
	mt := random.NewMersenneTwister()

	// start guessing from 1 year ago
	unixnow := time.Now().Unix()
	i := uint64(unixnow - 3600*24) // test 2 day's range
	j := uint64(unixnow + 3600*24)

	for ; i < j; i++ {
		if i%5000 == 0 {
			fmt.Println("test seed:", i)
		}

		mt.Seed(i)

		if mt.Next() == n {
			return i
		}
	}

	return 0
}

func main() {
	unixnow := time.Now().Unix()

	rand.Seed(0)
	n := rand.Intn(1000) + 40

	secretTimestamp := uint64(unixnow) + uint64(n)

	mt := random.NewMersenneTwister()
	mt.Seed(uint64(secretTimestamp))

	number := mt.Next()

	for i := 0; i < 20; i++ {
		fmt.Printf("mt1 %03d %d\n", i, mt.Next())
	}

	recoveredSeed := crackSeed(number)
	fmt.Println("recovered seed:", recoveredSeed)

	mt.Seed(recoveredSeed)
	mt.Next()
	for i := 0; i < 20; i++ {
		fmt.Printf("mt2 %03d %d\n", i, mt.Next())
	}
}
