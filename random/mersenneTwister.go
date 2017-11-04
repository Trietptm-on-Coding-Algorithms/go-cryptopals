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
	mt []uint64

	index int
}

func NewMersenneTwister() *MersenneTwister {
	return &MersenneTwister{
		mt:    make([]uint64, n),
		index: indexUnseeded,
	}
}

func (m *MersenneTwister) Seed(seed uint64) {
	m.index = n
	m.mt[0] = seed

	for i := 1; i < n; i++ {
		m.mt[i] = (f*(m.mt[i-1]^(m.mt[i-1]>>(w-2))) + uint64(i))
	}
}

func (m *MersenneTwister) Next() uint64 {
	if m.index == indexUnseeded {
		panic("never seeded")
	}

	if m.index == n {
		// twist
		m.twist()
	}

	y := m.mt[m.index]
	y = y ^ ((y >> u) & d)
	y = y ^ ((y << s) & b)
	y = y ^ ((y << t) & c)
	y = y ^ (y >> l)

	m.index++

	return y
}

func (self *MersenneTwister) twist() {
	MT := self.mt
	for i := 0; i < n; i++ {
		x := (MT[i] & upperMask) + (MT[(i+1)%n] & lowerMask)
		xA := x >> 1

		if x%2 != 0 {
			xA = xA ^ a
		}

		MT[i] = MT[(i+m)%n] ^ xA
	}

	self.index = 0
}
