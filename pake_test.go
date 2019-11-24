/*
Copyright (c) 2019 SILVANO ZAMPARDI
All rights reserved.
This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
*/

package pake

import (
	"crypto/elliptic"
	"crypto/sha512"
	"hash"
	"testing"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/stretchr/testify/assert"
	"github.com/tscholl2/siec"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/sha3"
)

func benchmarkPAKE(b *testing.B, eC EC, h func() hash.Hash) {
	for i := 0; i < b.N; i++ {
		k := _bytes(32)
		// initialize A
		A, _ := New(k, 0, eC, h)
		// initialize B
		B, _ := New(k, 1, eC, h)
		// send A's stuff to B
		B.Import(A.Export())
		// send B's stuff to A
		A.Import(B.Export())
		// send A's stuff back to B
		B.Import(A.Export())
	}
}

func BenchmarkPAKE_P256_SHA3_512(b *testing.B) {
	benchmarkPAKE(b, elliptic.P256(), sha3.New512)
}

func BenchmarkPAKE_P256_SHA2_512(b *testing.B) {
	benchmarkPAKE(b, elliptic.P256(), sha512.New)
}

func BenchmarkPAKE_P384_SHA3_512(b *testing.B) {
	benchmarkPAKE(b, elliptic.P384(), sha3.New512)
}

func BenchmarkPAKE_P384_SHA2_512(b *testing.B) {
	benchmarkPAKE(b, elliptic.P384(), sha512.New)
}

func BenchmarkPAKE_P521_SHA3_512(b *testing.B) {
	benchmarkPAKE(b, elliptic.P521(), sha3.New512)
}

func BenchmarkPAKE_P521_SHA2_512(b *testing.B) {
	benchmarkPAKE(b, elliptic.P521(), sha512.New)
}

func BenchmarkPAKE_SECP256K1_SHA3_512(b *testing.B) {
	benchmarkPAKE(b, secp256k1.S256(), sha3.New512)
}

func BenchmarkPAKE_SECP256K1_SHA2_512(b *testing.B) {
	benchmarkPAKE(b, secp256k1.S256(), sha512.New)
}

func BenchmarkPAKE_SIEC_SHA3_512(b *testing.B) {
	benchmarkPAKE(b, siec.SIEC255(), sha3.New512)
}

func BenchmarkPAKE_SIEC_SHA2_512(b *testing.B) {
	benchmarkPAKE(b, siec.SIEC255(), sha512.New)
}

func TestError(t *testing.T) {
	A, err := New([]byte{1, 2, 3}, 0, nil, nil)
	assert.Nil(t, err)
	A, err = New([]byte{1, 2, 3}, 0, elliptic.P224(), nil)
	assert.NotNil(t, err)
	_, err = A.Key()
	assert.NotNil(t, err)
	B, err := New([]byte{1, 2, 3}, 0, elliptic.P521(), nil)
	assert.Nil(t, err)
	assert.NotNil(t, B.Import(A.Export()))
	assert.False(t, A.IsVerified())
	assert.NotNil(t, B.Import([]byte("{1:1}")))
}

func TestThatForSomeReasonCurve224IsFailing(t *testing.T) {
	A, err := New([]byte{1, 2, 3}, 0, elliptic.P224(), nil)
	assert.NotNil(t, err)
	// initialize B
	B, err := New([]byte{1, 2, 3}, 1, elliptic.P224(), nil)
	assert.NotNil(t, err)
	// send A's stuff to B
	B.Import(A.Export())
	// send B's stuff to A
	A.Import(B.Export())
	// send A's stuff back to B
	B.Import(A.Export())
	s1, err := A.Key()
	assert.Nil(t, err)
	t.Logf("%s key A %x", elliptic.P224().Params().Name, s1)
	s1B, err := B.Key()
	assert.Nil(t, err)
	t.Logf("%s key B %x", elliptic.P224().Params().Name, s1B)
	assert.NotEqual(t, s1, s1B)
}

func TestKeyString(t *testing.T) {
	curves := map[string]EC{
		// elliptic.P224() nope!
		"p256":      elliptic.P256(),
		"p384":      elliptic.P384(),
		"p512":      elliptic.P521(),
		"secp256k1": secp256k1.S256(),
		"siec":      siec.SIEC255(),
	}
	k := _bytes(32) // max supported by secp256k1
	t.Logf("using weak key %x, bcrypt cost %d", k, bcrypt.DefaultCost)
	for n, curve := range curves {
		A, err := New(k, 0, curve, nil)
		assert.Nil(t, err)
		// initialize B
		B, err := New(k, 1, curve, nil)
		assert.Nil(t, err)
		// send A's stuff to B
		B.Import(A.Export())
		// send B's stuff to A
		A.Import(B.Export())
		// send A's stuff back to B
		B.Import(A.Export())
		s1, err := A.Key()
		assert.Nil(t, err)
		t.Logf("%s key A %x", n, s1)
		s1B, err := B.Key()
		assert.Nil(t, err)
		t.Logf("%s key B %x", n, s1B)
		assert.Equal(t, s1, s1B)
		// initialize A
		A, _ = New([]byte{1, 2, 3}, 0, curve, nil)
		// initialize B
		B, _ = New([]byte{1, 2, 3}, 1, curve, nil)
		// send A's stuff to B
		B.Import(A.Export())
		// send B's stuff to A
		A.Import(B.Export())
		// send A's stuff back to B
		B.Import(A.Export())
		s2, err := A.Key()
		assert.Nil(t, err)
		assert.NotEqual(t, s1, s2)
		assert.True(t, A.IsVerified())
		assert.True(t, B.IsVerified())
	}
}
