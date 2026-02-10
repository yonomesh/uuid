package uuid

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

var cachedMs atomic.Uint64
var shardAutoInc atomic.Uint32

const counterShards = 64

func init() {
	go func() {
		for {
			cachedMs.Store(uint64(time.Now().UnixMilli()))
			time.Sleep(500 * time.Microsecond) // 每 0.5ms 更新一次
		}
	}()
}

const (
	v7CounterMax = 1 << 12 // 4096
	// Size of pre-fetched random buffer to reduce calls to rand.Reader
	randBufSize = 8192
)

// v7State stores the random number buffer and state for each per-P context
type v7State struct {
	id uint32
	// Accessed only by the current P; no atomic operations needed.
	lastMs  uint64
	counter uint16
	buf     [randBufSize]byte
	idx     int
}

type shard struct {
	lastMs  atomic.Uint64 // 每个分片记录自己的毫秒数
	counter atomic.Uint32
	_       [48]byte // 补齐到 64 字节，防止伪共享
}

type gen struct {
	rand io.Reader
	pool sync.Pool

	// 将单一计数器扩展为数组，并进行 Padding
	// 每个分片占据一个独立的 Cache Line (64字节)
	lastMs atomic.Uint64
	_      [56]byte

	// 分片计数器
	shards [counterShards]shard
}

func newDefaultGen() *gen {
	g := &gen{
		rand: rand.Reader,
	}
	g.pool.New = func() any {
		// 每次 Pool 创建新对象时，id 递增，确保均匀分布在 64 个分片
		id := shardAutoInc.Add(1) % counterShards
		b := &v7State{
			id:  id,
			idx: randBufSize, // 触发第一次填充
		}
		return b
	}
	return g
}

var defaultGen = newDefaultGen()

// fill 从 Pool 中获取缓冲区并读取随机字节
func (g *gen) fill(dest []byte) error {
	vbuf := g.pool.Get().(*v7State)

	// 如果缓冲区不够，重新填满
	if vbuf.idx+len(dest) > randBufSize {
		if _, err := io.ReadFull(g.rand, vbuf.buf[:]); err != nil {
			g.pool.Put(vbuf) // 即使失败也放回去，或者丢弃
			return err
		}
		vbuf.idx = 0
	}

	copy(dest, vbuf.buf[vbuf.idx:vbuf.idx+len(dest)])
	vbuf.idx += len(dest)

	// 使用完后放回池中
	g.pool.Put(vbuf)
	return nil
}

func (g *gen) NewV7() (UUID, error) {
	s := g.pool.Get().(*v7State)

	// 索引获取
	sd := &g.shards[s.id]

	var now uint64
	var currentCounter uint32

	// 局部化单调性控制
	for {
		now = cachedMs.Load()
		sLast := sd.lastMs.Load()

		if now > sLast {
			if sd.lastMs.CompareAndSwap(sLast, now) {
				sd.counter.Store(0)
				currentCounter = 0
				break
			}
			continue
		}

		// 毫秒内：只在分片内部争抢，竞争压力降至 1/64
		now = sLast
		currentCounter = sd.counter.Add(1)
		if currentCounter < v7CounterMax {
			break
		}

		// 极端溢出处理
		runtime.Gosched()
		now = uint64(time.Now().UnixMilli())
	}

	// 随机数填充（利用 Pool 的空间换取 io.Reader 的系统调用时间）
	if s.idx+10 > randBufSize {
		if _, err := io.ReadFull(g.rand, s.buf[:]); err != nil {
			g.pool.Put(s)
			return NilUUID, err
		}
		s.idx = 0
	}

	var u UUID

	// 一次性填充 u[0:7] (其中 u[0:5] 是我们要的时间戳)
	binary.BigEndian.PutUint64(u[:8], now<<16)

	// 覆盖 u[6:15]，把刚才 PutUint64 写入 u[6:7] 的多余数据抹掉
	copy(u[6:], s.buf[s.idx:s.idx+10])
	s.idx += 10

	// 位运算合并 (Version 7 + 12bit Counter)
	u[6] = 0x70 | (byte(currentCounter>>8) & 0x0F)
	u[7] = byte(currentCounter)
	u[8] = (u[8] & 0x3F) | 0x80

	g.pool.Put(s)
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
	u.SetVersion(V7)

	//override first 2 bits of byte[8] for the variant
	u.SetVariant(VariantRFC9562)

	return u, nil
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
	u.SetVersion(V4)
	u.SetVariant(VariantRFC9562)
	return u, nil
}
