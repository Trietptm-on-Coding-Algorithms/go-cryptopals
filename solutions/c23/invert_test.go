package main

import (
	"math/rand"
	"testing"
	"time"

	"github.com/hayeah/go-cryptopals/random"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInvertRightShift(tt *testing.T) {
	is := assert.New(tt)

	rand.Seed(time.Now().UnixNano())

	// y := uint64(0x543dc6df0fa263e5)
	// shift := uint(9)
	// mask := uint64(0x111111111111)

	// y2 := y ^ ((y >> shift) & mask)
	// yRecovered := invertRightShiftXor(y2, shift, mask)

	// is.Equal(y, yRecovered, "y=0x%016x shift=%d", y, shift)

	for i := 0; i < 100000; i++ {
		y := rand.Uint64()
		// ensure shift is bigger than 8 bits. (0 .. 64]
		shift := uint(rand.Uint32()%56) + 9
		mask := rand.Uint64()

		y2 := y ^ ((y >> shift) & mask)
		yRecovered := invertRightShiftXor(y2, shift, mask)

		// fmt.Printf("y2 = 0x%016x\n", y2)
		// fmt.Printf("yRecovered: 0x%016x\n", yRecovered)

		is.Equal(y, yRecovered, "y=0x%016x shift=%d", y, shift)

	}
}

func TestInvertLeftShift(tt *testing.T) {
	is := assert.New(tt)

	rand.Seed(time.Now().UnixNano())

	for i := 0; i < 100000; i++ {
		y := rand.Uint64()
		// ensure shift is bigger than 8 bits. (0 .. 64]
		shift := uint(rand.Uint32()%56) + 9
		mask := rand.Uint64()

		y2 := y ^ ((y << shift) & mask)
		yRecovered := invertLeftShiftXor(y2, shift, mask)

		// fmt.Printf("y2 = 0x%016x\n", y2)
		// fmt.Printf("yRecovered: 0x%016x\n", yRecovered)

		is.Equal(y, yRecovered, "y=0x%016x shift=%d", y, shift)

	}
}

func TestRecoverState(tt *testing.T) {
	is := assert.New(tt)

	rand.Seed(time.Now().UnixNano())

	for i := 0; i < 10000; i++ {
		y := rand.Uint64()
		y2 := stateToNumber(y)
		recoveredY := numberToState(y2)

		is.Equal(y, recoveredY)
	}
}

func TestMersenneTwisterCracker(tt *testing.T) {
	stateSize := 312
	is := require.New(tt)

	rand.Seed(time.Now().UnixNano())

	for i := 0; i < 100; i++ {
		r := random.NewMersenneTwister()
		r.Seed(rand.Uint64())

		limit := int(rand.Intn(stateSize))
		for i := 0; i < limit; i++ {
			r.Next()
		}

		r2, err := CrackMersenneTwister(r)
		is.NoError(err)

		for k := 0; k < stateSize*3; k++ {
			is.Equal(r.Next(), r2.Next())
		}
	}
}
