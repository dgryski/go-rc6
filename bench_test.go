package rc6

import (
	"testing"
)

var sink uint64

func BenchmarkEncrypt(b *testing.B) {

	k := make([]byte, 16)

	c, _ := New(k)

	cipher := c.(*rc6cipher)

	p := make([]byte, 16)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		cipher.Encrypt(p, p)
	}

	sink += uint64(p[0])
}

func BenchmarkEncryptASM(b *testing.B) {

	k := make([]byte, 16)

	c, _ := New(k)

	cipher := c.(*rc6cipher)

	p := make([]byte, 16)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		EncryptASM(cipher, p, p)
	}

	sink += uint64(p[0])
}

func BenchmarkDecrypt(b *testing.B) {

	k := make([]byte, 16)

	c, _ := New(k)

	cipher := c.(*rc6cipher)

	p := make([]byte, 16)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		cipher.Decrypt(p, p)
	}

	sink += uint64(p[0])
}
