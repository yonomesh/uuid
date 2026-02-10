package uuid

import "testing"

func BenchmarkNewV7Lazy(b *testing.B) {
	gen := newDefaultGen()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = gen.NewV7Lazy()
		}
	})
}

func BenchmarkNewV7(b *testing.B) {
	gen := newDefaultGen() // 对应刚才改进的 sync.Pool 实现
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = gen.NewV7()
		}
	})
}
