// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs1

import (
	"crypto/rsa"
	"math/big"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/internal/keys"
	"github.com/pduveau/gocert/pkerr"
)

// ParsePKCS1PrivateKey parses an [RSA] private key in PKCS #1, ASN.1 DER form.
//
// This kind of key is commonly encoded in PEM blocks of type "RSA PRIVATE KEY".
func ParsePKCS1PrivateKey(der []byte) (*rsa.PrivateKey, pkerr.Kerror) {
	var priv keys.Pkcs1PrivateKey
	rest, err := asn1.Unmarshal(der, &priv)
	if len(rest) > 0 {
		return nil, pkerr.NewErrAsn1Syntax("trailing data")
	}
	if err != nil {
		if _, err := asn1.Unmarshal(der, &keys.EcPrivateKey{}); err == nil {
			return nil, pkerr.NewErrFailToParsePrivateKeyGotoECP()
		}
		if _, err := asn1.Unmarshal(der, &keys.Pkcs8{}); err == nil {
			return nil, pkerr.NewErrFailToParsePrivateKeyGotoPKCS8()
		}
		return nil, err
	}

	if priv.Version > 1 {
		return nil, pkerr.NewErrUnknownPrivateKeyVersion(priv.Version)
	}

	if priv.N.Sign() <= 0 || priv.D.Sign() <= 0 || priv.P.Sign() <= 0 || priv.Q.Sign() <= 0 ||
		priv.Dp != nil && priv.Dp.Sign() <= 0 ||
		priv.Dq != nil && priv.Dq.Sign() <= 0 ||
		priv.Qinv != nil && priv.Qinv.Sign() <= 0 {
		return nil, pkerr.NewErrRSAInvalidModulus()
	}

	key := new(rsa.PrivateKey)
	key.PublicKey = rsa.PublicKey{
		E: priv.E,
		N: priv.N,
	}

	key.D = priv.D
	key.Primes = make([]*big.Int, 2+len(priv.AdditionalPrimes))
	key.Primes[0] = priv.P
	key.Primes[1] = priv.Q
	key.Precomputed.Dp = priv.Dp
	key.Precomputed.Dq = priv.Dq
	key.Precomputed.Qinv = priv.Qinv
	for i, a := range priv.AdditionalPrimes {
		if a.Prime.Sign() <= 0 {
			return nil, pkerr.NewErrRSAInvalidPublicExponent()
		}
		key.Primes[i+2] = a.Prime
		// We ignore the other two values because rsa will calculate
		// them as needed.
	}

	key.Precompute()
	return key, pkerr.NewErrNative(key.Validate())
}

// MarshalPKCS1PrivateKey converts an [RSA] private key to PKCS #1, ASN.1 DER form.
//
// This kind of key is commonly encoded in PEM blocks of type "RSA PRIVATE KEY".
// For a more flexible key format which is not [RSA] specific, use
// [MarshalPKCS8PrivateKey].
//
// The key must have passed validation by calling [rsa.PrivateKey.Validate]
// first. MarshalPKCS1PrivateKey calls [rsa.PrivateKey.Precompute], which may
// modify the key if not already precomputed.
func MarshalPKCS1PrivateKey(key *rsa.PrivateKey) []byte {
	key.Precompute()

	version := 0
	if len(key.Primes) > 2 {
		version = 1
	}

	priv := keys.Pkcs1PrivateKey{
		Version: version,
		N:       key.N,
		E:       key.PublicKey.E,
		D:       key.D,
		P:       key.Primes[0],
		Q:       key.Primes[1],
		Dp:      key.Precomputed.Dp,
		Dq:      key.Precomputed.Dq,
		Qinv:    key.Precomputed.Qinv,
	}

	priv.AdditionalPrimes = make([]keys.Pkcs1AdditionalRSAPrime, len(key.Precomputed.CRTValues))
	for i, values := range key.Precomputed.CRTValues {
		priv.AdditionalPrimes[i].Prime = key.Primes[2+i]
		priv.AdditionalPrimes[i].Exp = values.Exp
		priv.AdditionalPrimes[i].Coeff = values.Coeff
	}

	b, _ := asn1.Marshal(priv)
	return b
}

// ParsePKCS1PublicKey parses an [RSA] public key in PKCS #1, ASN.1 DER form.
//
// This kind of key is commonly encoded in PEM blocks of type "RSA PUBLIC KEY".
func ParsePKCS1PublicKey(der []byte) (*rsa.PublicKey, pkerr.Kerror) {
	var pub keys.Pkcs1PublicKey
	rest, err := asn1.Unmarshal(der, &pub)
	if err != nil {
		if _, err := asn1.Unmarshal(der, &keys.PublicKeyInfo{}); err == nil {
			return nil, pkerr.NewErrFailToParsePublicKeyGotoPKIX()
		}
		return nil, err
	}
	if len(rest) > 0 {
		return nil, pkerr.NewErrAsn1Syntax("trailing data")
	}

	if pub.N.Sign() <= 0 || pub.E <= 0 {
		return nil, pkerr.NewErrRSAInvalidPublicExponent()
	}
	if pub.E > 1<<31-1 {
		return nil, pkerr.NewErrRSAInvalidPublicExponent()
	}

	return &rsa.PublicKey{
		E: pub.E,
		N: pub.N,
	}, nil
}

// MarshalPKCS1PublicKey converts an [RSA] public key to PKCS #1, ASN.1 DER form.
//
// This kind of key is commonly encoded in PEM blocks of type "RSA PUBLIC KEY".
func MarshalPKCS1PublicKey(key *rsa.PublicKey) []byte {
	derBytes, _ := asn1.Marshal(keys.Pkcs1PublicKey{
		N: key.N,
		E: key.E,
	})
	return derBytes
}
