/*
Copyright (c) 2019 SILVANO ZAMPARDI
All rights reserved.
This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
*/

package pake

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"hash"
	"io"
	"math/big"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/sha3"
)

// PAKE keeps public and private variables by only transmitting between parties after marshaling.
// References:
// - [Figure 21/15] https://crypto.stanford.edu/~dabo/cryptobook/BonehShoup_0_4.pdf
// - [Slide 11] http://www.lothar.com/~warner/MagicWormhole-PyCon2016.pdf
type PAKE struct {
	// Public variables
	Role       int // initiator is 0, receiver is 1
	Uᵤ, Uᵥ     *big.Int
	Vᵤ, Vᵥ     *big.Int
	Xᵤ, Xᵥ     *big.Int
	Yᵤ, Yᵥ     *big.Int
	HkA, HkB   []byte
	Vpwᵤ, Vpwᵥ *big.Int
	Upwᵤ, Upwᵥ *big.Int
	Aα         []byte
	Aαᵤ, Aαᵥ   *big.Int
	Zᵤ, Zᵥ     *big.Int
	// Private variables
	curve      EC               // make sure both parties are using the same curve
	secret     []byte           // the initial weak key
	hash       func() hash.Hash // make sure both parties are using the same func() hash.Hash
	sum        []byte           // the session key
	isVerified bool             // the session key validity
}

// Public returns the public variables of PAKE
func (p *PAKE) Public() *PAKE {
	return &PAKE{
		Role: p.Role,
		Uᵤ:   p.Uᵤ,
		Uᵥ:   p.Uᵥ,
		Vᵤ:   p.Vᵤ,
		Vᵥ:   p.Vᵥ,
		Xᵤ:   p.Xᵤ,
		Xᵥ:   p.Xᵥ,
		Yᵤ:   p.Yᵤ,
		Yᵥ:   p.Yᵥ,
		HkA:  p.HkA,
		HkB:  p.HkB,
	}
}

// EC is a general curve which allows other elliptic curves to be used with PAKE.
// The curve can be any curve that implements Add, ScalarBaseMult, ScalarMult, IsOnCurve.
type EC interface {
	Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int)
	ScalarBaseMult(k []byte) (*big.Int, *big.Int)
	ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int)
	IsOnCurve(x, y *big.Int) bool
}

// SetCurve is used when unmarshaling the whole private struct.
// The curve can be any curve that implements Add, ScalarBaseMult, ScalarMult, IsOnCurve.
func (p *PAKE) SetCurve(eC EC) {
	p.curve = eC
}

// New will take the secret weak passphrase  to initialize the points on the elliptic curve.
// The role is set to either 0 for the sender or 1 for the recipient.
// The curve can be any curve that implements Add, ScalarBaseMult, ScalarMult, IsOnCurve.
// nil curve will default to elliptic.P512
// nil hash will default to SHA3_512, be mindful that this results in 64b session keys
func New(key []byte, role int, curve EC, hash func() hash.Hash) (p *PAKE, err error) {
	p = new(PAKE)
	if hash == nil {
		hash = sha3.New512
	}
	if curve == nil {
		curve = elliptic.P521()
	}
	if curve == elliptic.P224() {
		err = fmt.Errorf("unsupported EC P224")
	}
	if len(key) < 3 {
		return nil, fmt.Errorf("shared key too short")
	}
	p.hash = hash
	if role == 1 {
		p.Role = 1
		p.curve = curve
		p.secret = key
	} else {
		p.Role = 0
		p.curve = curve
		p.secret = key
		p.Uᵤ, p.Uᵥ = p.curve.ScalarBaseMult(_bytes(8))
		p.Vᵤ, p.Vᵥ = p.curve.ScalarBaseMult(_bytes(8))
		if !p.curve.IsOnCurve(p.Uᵤ, p.Uᵥ) {
			return nil, fmt.Errorf("U values not on curve")
		}
		if !p.curve.IsOnCurve(p.Vᵤ, p.Vᵥ) {
			return nil, fmt.Errorf("V values not on curve")
		}
		// STEP: A computes X
		p.Vpwᵤ, p.Vpwᵥ = p.curve.ScalarMult(p.Vᵤ, p.Vᵥ, p.secret)
		p.Upwᵤ, p.Upwᵥ = p.curve.ScalarMult(p.Uᵤ, p.Uᵥ, p.secret)
		p.Aα = _bytes(8)
		p.Aαᵤ, p.Aαᵥ = p.curve.ScalarBaseMult(p.Aα)
		p.Xᵤ, p.Xᵥ = p.curve.Add(p.Upwᵤ, p.Upwᵥ, p.Aαᵤ, p.Aαᵥ) // "X"
		// now X should be sent to B
	}
	return p, err
}

var bcryptCost = 10

// SetBCryptCost allows you to change the bcrypt cost/iterations. Default is 10.
func SetBCryptCost(n int) { bcryptCost = n }

var randR = rand.Reader

// SetRandomReader allows you to change the randomness source. Default is crypto/rand.Reader.
func SetRandomReader(r io.Reader) { randR = r }

// Export gob-encode the PAKE structure and hide private variables.
func (p *PAKE) Export() []byte {
	var r bytes.Buffer
	if err := gob.NewEncoder(&r).Encode(p.Public()); err == nil {
		return r.Bytes()
	}
	return nil
}

// Update will update itself with the other parties' Export() and determine what stage and what to generate.
func (p *PAKE) Update(qBytes []byte) (err error) {
	var q *PAKE
	if err = gob.NewDecoder(bytes.NewBuffer(qBytes)).Decode(&q); err != nil {
		return err
	}
	if p.Role == q.Role {
		return fmt.Errorf("cannot have its own role")
	}
	p.isVerified = false
	if p.Role == 1 {
		// initial step for B
		if p.Uᵤ == nil && q.Uᵤ != nil {
			// copy over public variables
			p.Uᵤ, p.Uᵥ = q.Uᵤ, q.Uᵥ
			p.Vᵤ, p.Vᵥ = q.Vᵤ, q.Vᵥ
			p.Xᵤ, p.Xᵥ = q.Xᵤ, q.Xᵥ
			// // confirm that U,V are on curve
			if !p.curve.IsOnCurve(p.Uᵤ, p.Uᵥ) {
				return fmt.Errorf("U values not on curve")
			}
			if !p.curve.IsOnCurve(p.Vᵤ, p.Vᵥ) {
				return fmt.Errorf("V values not on curve")
			}
			// STEP: B computes Y
			p.Vpwᵤ, p.Vpwᵥ = p.curve.ScalarMult(p.Vᵤ, p.Vᵥ, p.secret)
			p.Upwᵤ, p.Upwᵥ = p.curve.ScalarMult(p.Uᵤ, p.Uᵥ, p.secret)
			p.Aα = _bytes(8) // randomly generated secret
			p.Aαᵤ, p.Aαᵥ = p.curve.ScalarBaseMult(p.Aα)
			p.Yᵤ, p.Yᵥ = p.curve.Add(p.Vpwᵤ, p.Vpwᵥ, p.Aαᵤ, p.Aαᵥ) // "Y"
			// STEP: B computes Z
			p.Zᵤ, p.Zᵥ = p.curve.Add(p.Xᵤ, p.Xᵥ, p.Upwᵤ, new(big.Int).Neg(p.Upwᵥ))
			p.Zᵤ, p.Zᵥ = p.curve.ScalarMult(p.Zᵤ, p.Zᵥ, p.Aα)
			// STEP: B computes k
			// H(pw,id_P,id_Q,X,Y,Z)
			HB := p.hash()
			_, err = HB.Write(p.secret)
			_, err = HB.Write(p.Xᵤ.Bytes())
			_, err = HB.Write(p.Xᵥ.Bytes())
			_, err = HB.Write(p.Yᵤ.Bytes())
			_, err = HB.Write(p.Yᵥ.Bytes())
			_, err = HB.Write(p.Zᵤ.Bytes())
			_, err = HB.Write(p.Zᵥ.Bytes())
			if err != nil {
				return err
			}
			// STEP: B computes k
			p.sum = HB.Sum(nil)
			p.HkB, err = bcrypt.GenerateFromPassword(p.sum, bcryptCost)
		} else if p.HkA == nil && q.HkA != nil {
			p.HkA = q.HkA
			// verify
			if err = bcrypt.CompareHashAndPassword(p.HkA, p.sum); err == nil {
				p.isVerified = true
			}
		}
	} else {
		if p.HkB == nil && q.HkB != nil {
			p.HkB = q.HkB
			p.Yᵤ, p.Yᵥ = q.Yᵤ, q.Yᵥ
			// STEP: A computes Z
			p.Zᵤ, p.Zᵥ = p.curve.Add(p.Yᵤ, p.Yᵥ, p.Vpwᵤ, new(big.Int).Neg(p.Vpwᵥ))
			p.Zᵤ, p.Zᵥ = p.curve.ScalarMult(p.Zᵤ, p.Zᵥ, p.Aα)
			// STEP: A computes k
			// H(pw,id_P,id_Q,X,Y,Z)
			HA := p.hash()
			_, err = HA.Write(p.secret)
			_, err = HA.Write(p.Xᵤ.Bytes())
			_, err = HA.Write(p.Xᵥ.Bytes())
			_, err = HA.Write(p.Yᵤ.Bytes())
			_, err = HA.Write(p.Yᵥ.Bytes())
			_, err = HA.Write(p.Zᵤ.Bytes())
			_, err = HA.Write(p.Zᵥ.Bytes())
			if err != nil {
				return err
			}
			p.sum = HA.Sum(nil)
			p.HkA, err = bcrypt.GenerateFromPassword(p.sum, bcryptCost)
			// STEP: A verifies that its session key matches B's
			// session key
			if err = bcrypt.CompareHashAndPassword(p.HkB, p.sum); err == nil {
				p.isVerified = true
			}
		}
	}
	return err
}

// Key returns the session Key, unless it was not generated.
// This function does not check the validity of the Key.
func (p *PAKE) Key() ([]byte, error) {
	if p.sum == nil {
		return nil, fmt.Errorf("session key not generated")
	}
	return p.sum, nil
}

// IsVerified returns whether or not the k has been generated AND it confirmed to be valid.
func (p *PAKE) IsVerified() bool {
	return p.isVerified
}

// _bytes guards the rand reader always checking that we have proper random []byte generated
// panics on any error.
func _bytes(size int) []byte {
	work := make([]byte, size*2)
	nsize, err := io.ReadFull(randR, work)
	if err != nil {
		panic(err)
	}
	if nsize != size*2 {
		panic("output random []byte size mismatch")
	}
	return work[size:]
}
