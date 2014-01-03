// Package rc6 implements the RC6 cipher
/*

For more information, please see:
    https://en.wikipedia.org/wiki/RC6
    http://www.emc.com/emc-plus/rsa-labs/historical/rc6-block-cipher.htm

*/
package rc6

import (
	"crypto/cipher"
	"strconv"
)

const (
	rounds    = 20
	roundKeys = 2*rounds + 4
)

type rc6cipher struct {
	rk [roundKeys]uint32
}

func rotl32(k uint32, rot uint32) uint32 {
	return (k << rot) | (k >> (32 - rot))
}

func rotr32(k uint32, rot uint32) uint32 {
	return (k >> rot) | (k << (32 - rot))
}

type KeySizeError int

func (k KeySizeError) Error() string { return "rc6: invalid key size " + strconv.Itoa(int(k)) }

// New returns a cipher.Block implementing RC6.  The key argument must be 16 bytes.
func New(key []byte) (cipher.Block, error) {

	if l := len(key); l != 16 {
		return nil, KeySizeError(l)
	}

	c := &rc6cipher{}

	const keyWords = 4

	var L [keyWords]uint32

	for i := 0; i < keyWords; i++ {
		L[i] = getUint32(key)
		key = key[4:]
	}

	copy(c.rk[:], skeytable)

	var A uint32
	var B uint32
	var i, j int

	for k := 0; k < 3*roundKeys; k++ {
		c.rk[i] = rotl32(c.rk[i]+(A+B), 3)
		A = c.rk[i]
		L[j] = rotl32(L[j]+(A+B), (A+B)&31)
		B = L[j]

		i = (i + 1) % roundKeys
		j = (j + 1) % keyWords
	}

	return c, nil
}

func (c *rc6cipher) BlockSize() int { return 16 }

func (c *rc6cipher) Encrypt(dst, src []byte) {

	A := getUint32(src)
	B := getUint32(src[4:])
	C := getUint32(src[8:])
	D := getUint32(src[12:])

	B = B + c.rk[0]
	D = D + c.rk[1]
	for i := 1; i <= rounds; i++ {
		t := rotl32(B*(2*B+1), 5)
		u := rotl32(D*(2*D+1), 5)
		A = rotl32((A^t), u&31) + c.rk[2*i]
		C = rotl32((C^u), t&31) + c.rk[2*i+1]
		A, B, C, D = B, C, D, A
	}
	A = A + c.rk[2*rounds+2]
	C = C + c.rk[2*rounds+3]

	putUint32(dst, A)
	putUint32(dst[4:], B)
	putUint32(dst[8:], C)
	putUint32(dst[12:], D)
}

func (c *rc6cipher) Decrypt(dst, src []byte) {

	A := getUint32(src)
	B := getUint32(src[4:])
	C := getUint32(src[8:])
	D := getUint32(src[12:])

	C = C - c.rk[2*rounds+3]
	A = A - c.rk[2*rounds+2]

	for i := rounds; i >= 1; i-- {
		A, B, C, D = D, A, B, C
		u := rotl32(D*(2*D+1), 5)
		t := rotl32(B*(2*B+1), 5)
		C = rotr32((C-c.rk[2*i+1]), t&31) ^ u
		A = rotr32((A-c.rk[2*i]), u&31) ^ t
	}
	D = D - c.rk[1]
	B = B - c.rk[0]

	putUint32(dst, A)
	putUint32(dst[4:], B)
	putUint32(dst[8:], C)
	putUint32(dst[12:], D)
}

// avoid pulling in encoding/binary

func getUint32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func putUint32(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

// skeytable computed from
/*

Pw = uint32(0xb7e15163)
Qw = uint32(0x9e3779b9)

    T = 2*(R+2);
    S[0] = Pw;
    for (i = 1 ; i < T ; i++)  {
        S[i] = S[i-1] + Qw;
    }
*/

var skeytable = []uint32{
	0xb7e15163, 0x5618cb1c, 0xf45044d5, 0x9287be8e, 0x30bf3847, 0xcef6b200, 0x6d2e2bb9, 0x0b65a572,
	0xa99d1f2b, 0x47d498e4, 0xe60c129d, 0x84438c56, 0x227b060f, 0xc0b27fc8, 0x5ee9f981, 0xfd21733a,
	0x9b58ecf3, 0x399066ac, 0xd7c7e065, 0x75ff5a1e, 0x1436d3d7, 0xb26e4d90, 0x50a5c749, 0xeedd4102,
	0x8d14babb, 0x2b4c3474, 0xc983ae2d, 0x67bb27e6, 0x05f2a19f, 0xa42a1b58, 0x42619511, 0xe0990eca,
	0x7ed08883, 0x1d08023c, 0xbb3f7bf5, 0x5976f5ae, 0xf7ae6f67, 0x95e5e920, 0x341d62d9, 0xd254dc92,
	0x708c564b, 0x0ec3d004, 0xacfb49bd, 0x4b32c376,
}
