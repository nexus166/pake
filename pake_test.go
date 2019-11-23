/*
Copyright (c) 2019 SILVANO ZAMPARDI
All rights reserved.
This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
*/

package pake

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/sha3"
)

func benchmarkPake(b *testing.B, eC elliptic.Curve, h func() hash.Hash) {
	for i := 0; i < b.N; i++ {
		// initialize A
		A, _ := New([]byte{1, 2, 3}, 0, eC, h, 1*time.Microsecond)
		// initialize B
		B, _ := New([]byte{1, 2, 3}, 1, eC, h, 1*time.Microsecond)
		// send A's stuff to B
		B.Update(A.Export())
		// send B's stuff to A
		A.Update(B.Export())
		// send A's stuff back to B
		B.Update(A.Export())
	}
}

func BenchmarkPake_P521_SHA3_512(b *testing.B) {
	benchmarkPake(b, elliptic.P521(), sha3.New512)
}

func BenchmarkPake_P521_SHA3_256(b *testing.B) {
	benchmarkPake(b, elliptic.P521(), sha3.New256)
}

func BenchmarkPake_P521_SHA2_512(b *testing.B) {
	benchmarkPake(b, elliptic.P521(), sha512.New)
}

func BenchmarkPake_P521_SHA2_256(b *testing.B) {
	benchmarkPake(b, elliptic.P521(), sha256.New)
}

func BenchmarkPake_P384_SHA3_512(b *testing.B) {
	benchmarkPake(b, elliptic.P384(), sha3.New512)
}

func BenchmarkPake_P384_SHA3_256(b *testing.B) {
	benchmarkPake(b, elliptic.P384(), sha3.New256)
}

func BenchmarkPake_P384_SHA2_512(b *testing.B) {
	benchmarkPake(b, elliptic.P384(), sha512.New)
}

func BenchmarkPake_P384_SHA2_256(b *testing.B) {
	benchmarkPake(b, elliptic.P384(), sha256.New)
}

func BenchmarkPake_P256_SHA3_512(b *testing.B) {
	benchmarkPake(b, elliptic.P256(), sha3.New512)
}

func BenchmarkPake_P256_SHA3_256(b *testing.B) {
	benchmarkPake(b, elliptic.P256(), sha3.New256)
}

func BenchmarkPake_P256_SHA2_512(b *testing.B) {
	benchmarkPake(b, elliptic.P256(), sha512.New)
}

func BenchmarkPake_P256_SHA2_256(b *testing.B) {
	benchmarkPake(b, elliptic.P256(), sha256.New)
}

func TestError(t *testing.T) {
	A, err := New([]byte{1, 2, 3}, 0, nil, nil, 1*time.Millisecond)
	assert.Nil(t, err)
	A, err = New([]byte{1, 2, 3}, 0, elliptic.P224(), nil)
	assert.NotNil(t, err)
	_, err = A.Key()
	assert.NotNil(t, err)
	B, err := New([]byte{1, 2, 3}, 0, elliptic.P521(), nil)
	assert.Nil(t, err)
	assert.NotNil(t, B.Update(A.Export()))
	assert.False(t, A.IsVerified())
	assert.NotNil(t, B.Update([]byte("{1:1}")))
}

func TestThatForSomeReasonCurve224IsFailing(t *testing.T) {
	A, err := New([]byte{1, 2, 3}, 0, elliptic.P224(), nil, 1*time.Millisecond)
	assert.NotNil(t, err)
	// initialize B
	B, err := New([]byte{1, 2, 3}, 1, elliptic.P224(), nil, 1*time.Millisecond)
	assert.NotNil(t, err)
	// send A's stuff to B
	B.Update(A.Export())
	// send B's stuff to A
	A.Update(B.Export())
	// send A's stuff back to B
	B.Update(A.Export())
	s1, err := A.Key()
	assert.Nil(t, err)
	t.Logf("key A %x", s1)
	s1B, err := B.Key()
	assert.Nil(t, err)
	t.Logf("key B %x", s1B)
	assert.NotEqual(t, s1, s1B)
}

func TestKeyString(t *testing.T) {
	curves := []elliptic.Curve{
		// elliptic.P224() nope!
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	}
	for _, curve := range curves {
		A, err := New([]byte{1, 2, 3}, 0, curve, nil, 1*time.Millisecond)
		assert.Nil(t, err)
		// initialize B
		B, err := New([]byte{1, 2, 3}, 1, curve, nil, 1*time.Millisecond)
		assert.Nil(t, err)
		// send A's stuff to B
		B.Update(A.Export())
		// send B's stuff to A
		A.Update(B.Export())
		// send A's stuff back to B
		B.Update(A.Export())
		s1, err := A.Key()
		assert.Nil(t, err)
		t.Logf("key A %x", s1)
		s1B, err := B.Key()
		assert.Nil(t, err)
		t.Logf("key B %x", s1B)
		assert.Equal(t, s1, s1B)
		// initialize A
		A, _ = New([]byte{1, 2, 3}, 0, curve, nil, 1*time.Millisecond)
		// initialize B
		B, _ = New([]byte{1, 2, 3}, 1, curve, nil, 1*time.Millisecond)
		// send A's stuff to B
		B.Update(A.Export())
		// send B's stuff to A
		A.Update(B.Export())
		// send A's stuff back to B
		B.Update(A.Export())
		s2, err := A.Key()
		assert.Nil(t, err)
		assert.NotEqual(t, s1, s2)
		assert.True(t, A.IsVerified())
		assert.True(t, B.IsVerified())
	}
}
