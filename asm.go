// +build ignore

package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
)

/*
func (c *rc6cipher) Encrypt(dst, src []byte) {
	_ = dst[15]
	_ = src[15]

	A := binary.LittleEndian.Uint32(src[:4])
	B := binary.LittleEndian.Uint32(src[4:8])
	C := binary.LittleEndian.Uint32(src[8:12])
	D := binary.LittleEndian.Uint32(src[12:16])

	B = B + c.rk[0]
	D = D + c.rk[1]
	for i := 1; i <= rounds; i++ {
		t := bits.RotateLeft32(B*(2*B+1), 5)
		u := bits.RotateLeft32(D*(2*D+1), 5)
		A = bits.RotateLeft32((A^t), int(u)) + c.rk[2*i]
		C = bits.RotateLeft32((C^u), int(t)) + c.rk[2*i+1]
		A, B, C, D = B, C, D, A
	}
	A = A + c.rk[2*rounds+2]
	C = C + c.rk[2*rounds+3]

	binary.LittleEndian.PutUint32(dst[:4], A)
	binary.LittleEndian.PutUint32(dst[4:8], B)
	binary.LittleEndian.PutUint32(dst[8:12], C)
	binary.LittleEndian.PutUint32(dst[12:16], D)
}
*/

var _ Register = GP32()

func main() {
	Package("github.com/dgryski/go-rc6")

	TEXT("EncryptASM", NOSPLIT, "func(c *rc6cipher, dst, src []byte)")

	/*
		regs := []GPVirtual{GP32(), GP32(), GP32(), GP32()}
		a, b, c, d := 0, 1, 2, 3
	*/

	a, b, c, d := GP32(), GP32(), GP32(), GP32()

	src := GP64()
	Load(Param("src").Base(), src)

	MOVL(Mem{Base: src}, a)
	MOVL(Mem{Base: src, Disp: 4}, b)
	MOVL(Mem{Base: src, Disp: 8}, c)
	MOVL(Mem{Base: src, Disp: 12}, d)

	rk := Load(Param("c"), GP64())

	ADDL(Mem{Base: rk}, b)
	ADDL(Mem{Base: rk, Disp: 4}, d)
	ADDQ(Imm(8), rk)

	idx := GP64()
	MOVQ(U32(0), idx)
	Label("loop")

	t := GP32()
	u := GP32()

	const (
		unroll = 1
		rounds = 20
	)

	if rounds%unroll != 0 {
		panic("bad unroll amount")
	}

	for i := 0; i < unroll; i++ {

		MOVL(b, t)
		IMULL(b, t)
		SHLL(Imm(1), t)
		ADDL(b, t)
		ROLL(Imm(5), t)

		MOVL(d, u)
		IMULL(d, u)
		SHLL(Imm(1), u)
		ADDL(d, u)
		ROLL(Imm(5), u)

		XORL(t, a)
		MOVB(u.As8(), CL)
		ROLL(CL, a)
		ADDL(Mem{Base: rk, Disp: 8 * i}, a)

		XORL(u, c)
		MOVB(t.As8(), CL)
		ROLL(CL, c)
		ADDL(Mem{Base: rk, Disp: 8*i + 4}, c)

		MOVL(a, t)
		MOVL(b, a)
		MOVL(c, b)
		MOVL(d, c)
		MOVL(t, d)
	}

	ADDQ(Imm(8*unroll), rk)
	ADDQ(Imm(unroll), idx)
	CMPQ(idx, Imm(rounds))
	JL(LabelRef("loop"))

	ADDL(Mem{Base: rk}, a)
	ADDL(Mem{Base: rk, Disp: 4}, c)

	dst := GP64()
	Load(Param("dst").Base(), dst)

	MOVL(a, Mem{Base: dst})
	MOVL(b, Mem{Base: dst, Disp: 4})
	MOVL(c, Mem{Base: dst, Disp: 8})
	MOVL(d, Mem{Base: dst, Disp: 12})

	RET()
	Generate()

}
