package main

import (
	"github.com/hayeah/go-cryptopals/random"
	"github.com/pkg/errors"
)

const (
	w = 64
	n = 312
	m = 156
	r = 31

	a = 0xB5026F5AA96619E9
	u = 29
	d = 0x5555555555555555
	s = 17
	b = 0x71D67FFFEDA60000
	t = 37
	c = 0xFFF7EEE000000000
	l = 43
	f = 6364136223846793005
)

func CrackMersenneTwister(r *random.MersenneTwister) (*random.MersenneTwister, error) {
	// n is total number of substates. Because of possible substate misalignment,
	// we'll need to recover up to n substates.
	//
	// We need to find the moment when the twister twist into a new state
	stateSize := 312
	states := make([]uint64, stateSize*2)
	mt := make([]uint64, stateSize)

	i := 0

	// generate first 312 states, then start testing for substate alignment
	for ; i < 312; i++ {
		n := r.Next()
		y := numberToState(n)
		states[i] = y
	}

	// NOTE: apparently j = 0 always succeeds... gathering 312 numbers then twist, will always yield next sequence of substates.
	for j := 0; j < stateSize; j++ {
		// fmt.Println("j", j)

		// assuming that current twister had already tempered j times

		// test if next generated number is the same as our guess.
		n := r.Next()

		copy(mt, states[j:])

		guessTwister := random.MersenneTwister{
			Mt:    mt,
			Index: stateSize, // always test if it is in alignment...
		}

		// fmt.Println("guess next")
		// spew.Dump("before twist Mt[:10]", r.Mt[:10])
		// spew.Dump("before twist Mt[:10]", guessTwister.Mt[:10])
		guessN := guessTwister.Next() // this should cause a twist.
		// spew.Dump("after twist Mt[:10]", r.Mt[:10])
		// spew.Dump("after twist  Mt[:10]", guessTwister.Mt[:10])

		if n == guessN {

			// fmt.Println("n, guessN", n, guessN)
			// fmt.Println("n, guessN", r.Next(), guessTwister.Next())
			// fmt.Println("n, guessN", r.Next(), guessTwister.Next())
			// fmt.Println("n, guessN", r.Next(), guessTwister.Next())

			// fmt.Println("r", r.Mt[0])
			// fmt.Println("guess r", guessTwister.Mt[0])
			return &guessTwister, nil
		}

		states[i] = numberToState(n)
		i++
	}

	return nil, errors.New("Failed to crack Mersenne Twister")
}

func stateToNumber(y uint64) uint64 {
	y = y ^ ((y >> u) & d)
	y = y ^ ((y << s) & b)
	y = y ^ ((y << t) & c)
	y = y ^ (y >> l)

	return y
}

func numberToState(y uint64) uint64 {
	// y = y ^ (y >> l)
	y = invertRightShiftXor(y, l, ^(uint64(0x0)))
	// y = y ^ ((y << t) & c)
	y = invertLeftShiftXor(y, t, c)
	// y = y ^ ((y << s) & b)
	y = invertLeftShiftXor(y, s, b)
	// y = y ^ ((y >> u) & d)
	y = invertRightShiftXor(y, u, d)
	return y
}

// Inverts y ^ ((y << shift) & mask)
func invertLeftShiftXor(y2 uint64, shift uint, mask uint64) uint64 {
	if shift <= 8 {
		// this algorithm only works if lower bytes don't influence higher bytes
		panic("shift must be greater than 8")
	}

	var y uint64

	for i := 7; i >= 0; i-- {
		// shift to get the desired byte
		pos := uint((7 - i) * 8)

	guessbyte:
		for j := 0; j <= 256; j++ {
			if j == 256 {
				panic("cannot find result")
			}

			// clear nth byte
			y &= ^(uint64(0xff) << pos)

			// set nth byte
			y |= uint64(j) << pos

			// DEBUG
			// fmt.Printf("set j=0x%01x 0x%016x\n", j, uint64(j)<<pos)
			// fmt.Printf("y = 0x%016x\n", y)

			y2test := y ^ ((y << shift) & mask)

			test := byte(y2>>pos) == byte(y2test>>pos)

			if test {
				break guessbyte
			}
		}
	}

	return y
}

// Inverts y ^ ((y >> shift) & mask)
func invertRightShiftXor(y2 uint64, shift uint, mask uint64) uint64 {
	if shift <= 8 {
		// this algorithm only works if lower bytes don't influence higher bytes
		panic("shift must be greater than 8")
	}

	var y uint64

	for i := 0; i < 8; i++ {
		// shift to get the desired byte
		pos := uint((7 - i) * 8)

	guessbyte:
		for j := 0; j <= 256; j++ {
			if j == 256 {
				panic("cannot find result")
			}

			// clear nth byte
			y &= ^(uint64(0xff) << pos)

			// set nth byte
			y |= uint64(j) << pos

			// DEBUG
			// fmt.Printf("set j=0x%01x 0x%016x\n", j, uint64(j)<<pos)
			// fmt.Printf("y = 0x%016x\n", y)

			y2test := y ^ ((y >> shift) & mask)

			test := byte(y2>>pos) == byte(y2test>>pos)

			if test {
				break guessbyte
			}
		}
	}

	return y
}
