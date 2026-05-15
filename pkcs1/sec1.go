// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs1

import (
	"crypto/ecdsa"
	"errors"

	"github.com/pduveau/gocert/keys"
	"github.com/pduveau/gocert/pkix"
)

// ParseECPrivateKey parses an EC private key in SEC 1, ASN.1 DER form.
//
// This kind of key is commonly encoded in PEM blocks of type "EC PRIVATE KEY".
func ParseECPrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	return keys.ParseECPrivateKey(nil, der)
}

// MarshalECPrivateKey converts an EC private key to SEC 1, ASN.1 DER form.
//
// This kind of key is commonly encoded in PEM blocks of type "EC PRIVATE KEY".
// For a more flexible key format which is not EC specific, use
// [MarshalPKCS8PrivateKey].
func MarshalECPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	oid, ok := pkix.OidFromNamedCurve(key.Curve)
	if !ok {
		return nil, errors.New("x509: unknown elliptic curve")
	}

	return keys.MarshalECPrivateKeyWithOID(key, oid)
}
