# pake

[![travis](https://travis-ci.org/nexus166/pake.svg?branch=master)](https://travis-ci.org/nexus166/pake) 
[![go report card](https://goreportcard.com/badge/github.com/nexus166/pake)](https://goreportcard.com/report/github.com/nexus166/pake)
[![Coverage Status](https://coveralls.io/repos/github/nexus166/pake/badge.svg)](https://coveralls.io/github/nexus166/pake)
[![godocs](https://godoc.org/github.com/nexus166/pake?status.svg)](https://godoc.org/github.com/nexus166/pake) 

## Overview

This library will help you allow two parties to generate a mutual secret key by using a weak key that is known to both beforehand (e.g. via some other channel of communication). This is a simple API for an implementation of password-authenticated key exchange (PAKE). 

I decided to fork [@schollz]'s fork because of some breaking changes:
- The default hashing function is now sha3.512. This means that SessionKeys are 64b.
- Functions signatures and names changed.
- [gob](https://golang.org/pkg/encoding/gob/) encoding is now used instead of JSON.
- Some Pake{} private variables are now actually private variables.
- Removed SIEC EC from library, I don't like external imports.

New functionalities:
- You can set any `io.Reader` as source of random data.
- You can change the bcrypt cost.
- You can provide any curve that implements Add, ScalarBaseMult, ScalarMult, IsOnCurve methods.
- You can provide any `func() hash.Hash` that will be used to validate the remote's input.

Defaults: *SHA3_512* & *CurveP512*

![algorithm](https://i.imgur.com/s7oQWVP.png)

This protocol is derived from [Dan Boneh and Victor Shoup's cryptography book](https://crypto.stanford.edu/~dabo/cryptobook/BonehShoup_0_4.pdf) (pg 789, "PAKE2 protocol). 
The *H(k)* is a bcrypt hashed session key, which only the keeper of a real session key can verify. Passing this between P and Q allows them to understand that the other party does indeed have the session key derived correctly through the PAKE protocol. The session key can then be used to encrypt a message because it has never passed between parties.

Anytime some part of the algorithm fails verification: i.e. the points are not along the elliptic curve, or if a hash from either party is not identified, a non-nil error is returned. 
When this happens, you should abort and start a PAKE session as it could have been compromised.



## Installation

```sh
go get -u github.com/nexus166/pake
```

## Usage 

```golang
// both parties should have a weak key
pw := []byte{1, 2, 3}

// initialize sender P ("0" indicates sender)
P, err := New(pw, 0, elliptic.P521())
check(err)

// initialize recipient Q ("1" indicates recipient)
Q, err := New(pw, 1, elliptic.P521())
check(err)

// first, P sends u to Q
err = Q.Update(P.Export())
check(err) // errors will occur when any part of the process fails

// Q computes k, sends H(k), v back to P
err = P.Update(Q.Export())
check(err)

// P computes k, H(k), sends H(k) to Q
err = Q.Update(P.Export())
check(err)

// both P and Q now have session key
Pk := P.Key()
Qk := Q.Key()

bytes.Equal(Pk, Qk) == true
```

## Thanks

Thanks [@tscholl2](https://github.com/tscholl2) for implementing the first version.
Thanks [@schollz](https://github.com/schollz) for implementing the second version.

## License

[MIT](./LICENSE)
