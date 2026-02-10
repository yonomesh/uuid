package uuid

type Generator interface {
	NewV4() (UUID, error)
	NewV7() (UUID, error)
}

// SetVersion sets the version bits
func (u *UUID) SetVersion(v byte) {
	u[6] = (u[6] & 0x0F) | (v << 4)
}

// SetVariant sets the variant bits.
func (u *UUID) SetVariant(v byte) {
	switch v {
	case VariantRFC9562: // 最常用的情况
		u[8] = (u[8] & 0x3f) | 0x80
	case VariantNCS:
		u[8] &= 0x7f
	case VariantMicrosoft:
		u[8] = (u[8] & 0x1f) | 0xc0
	default: // VariantFuture
		u[8] = (u[8] & 0x1f) | 0xe0
	}
}
