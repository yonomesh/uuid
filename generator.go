package uuid

import (
	"crypto/rand"
	"io"
	"time"
)

type Generator interface {
	NewV4() (UUID, error)
	// NewV7() UUID
	NewV7Lazy() (UUID, error)
}

func (u *UUID) setVersion(v byte) {
	u[6] = (u[6] & 0x0F) | (v << 4)
}

// SetVariant sets the variant bits.
func (u *UUID) setVariant(v byte) {
	switch v {
	case VariantNCS:
		u[8] = (u[8]&(0xff>>1) | (0x00 << 7))
	case VariantRFC9562:
		u[8] = (u[8]&(0xff>>2) | (0x02 << 6))
	case VariantMicrosoft:
		u[8] = (u[8]&(0xff>>3) | (0x06 << 5))
	case VariantFuture:
		fallthrough
	default:
		u[8] = (u[8]&(0xff>>3) | (0x07 << 5))
	}
}

// Difference in 100-nanosecond intervals between
// UUID epoch (October 15, 1582) and Unix epoch (January 1, 1970).
const epochStart = 122192928000000000

type gen struct {
	rand io.Reader
}

var defaultGen = newDefaultGen()

var _ Generator = (*gen)(nil)

// type GenOption func(*defaultGen)

func newDefaultGen() *gen {
	return &gen{
		rand: rand.Reader,
	}
}

func (g *gen) NewV4() (UUID, error) {
	// https://datatracker.ietf.org/doc/html/rfc9562#name-uuid-version-7
	//
	// 	UUIDv4 {
	//     entropy_hi(0..47),
	//     version(48..51),
	//     entropy_mid(52..63),
	//     variant(64..65),
	//     entropy_lo(66..127)
	// }
	u := UUID{}
	if _, err := io.ReadFull(g.rand, u[:]); err != nil {
		return NilUUID, err
	}
	u.setVersion(V4)
	u.setVariant(VariantRFC9562)
	return u, nil
}

func (g *gen) NewV7Lazy() (UUID, error) {
	// https://datatracker.ietf.org/doc/html/rfc9562#name-uuid-version-7
	//
	// UUIDv7 {
	//     unix_ts_ms(0..47),
	//     version(48..51),
	//     rand_a(12),
	//     variant(64..65),
	//     rand_b(66..127)
	// }
	u := UUID{}

	// UUIDv7 uses a 48-bit Unix timestamp in milliseconds.
	ms := uint64(time.Now().UnixMilli())
	// Bytes 0-5: 48-bit big-endian Unix millisecond timestamp
	u[0] = byte(ms >> 40)
	u[1] = byte(ms >> 32)
	u[2] = byte(ms >> 24)
	u[3] = byte(ms >> 16)
	u[4] = byte(ms >> 8)
	u[5] = byte(ms)

	//cryptographically random tail
	if _, err := io.ReadFull(g.rand, u[6:16]); err != nil {
		return NilUUID, err
	}

	//override first 4bits of u[6].
	u.setVersion(V7)

	//override first 2 bits of byte[8] for the variant
	u.setVariant(VariantRFC9562)

	return u, nil
}
