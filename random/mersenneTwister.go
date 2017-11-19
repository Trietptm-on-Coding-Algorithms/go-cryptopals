package random

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

var (
	lowerMask uint64 = 0x7FFFFFFF
	upperMask uint64 = ^lowerMask
)

const indexUnseeded = -1

type MersenneTwister struct {
	Mt []uint64

	Index int
}

func NewMersenneTwister() *MersenneTwister {
	return &MersenneTwister{
		Mt:    make([]uint64, n),
		Index: indexUnseeded,
	}
}

func (m *MersenneTwister) Seed(seed uint64) {
	m.Index = n
	m.Mt[0] = seed

	for i := 1; i < n; i++ {
		m.Mt[i] = (f*(m.Mt[i-1]^(m.Mt[i-1]>>(w-2))) + uint64(i))
	}
}

func (m *MersenneTwister) Next() uint64 {
	if m.Index == indexUnseeded {
		panic("never seeded")
	}

	if m.Index == n {
		// twist
		m.twist()
	}

	y := m.Mt[m.Index]
	y = y ^ ((y >> u) & d)
	y = y ^ ((y << s) & b)
	y = y ^ ((y << t) & c)
	y = y ^ (y >> l)

	m.Index++

	return y
}

func (self *MersenneTwister) twist() {
	MT := self.Mt
	for i := 0; i < n; i++ {
		x := (MT[i] & upperMask) + (MT[(i+1)%n] & lowerMask)
		xA := x >> 1

		if x%2 != 0 {
			xA = xA ^ a
		}

		MT[i] = MT[(i+m)%n] ^ xA
	}

	self.Index = 0
}
