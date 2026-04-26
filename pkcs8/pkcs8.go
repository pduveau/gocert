// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs8

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/internal/keys"
	"github.com/pduveau/gocert/pkcs1"
	"github.com/pduveau/gocert/pkcs5"
	"github.com/pduveau/gocert/pkerr"
	"github.com/pduveau/gocert/pkix"
)

type encryptedPrivateKeyInfo struct {
	EncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedData       []byte
}

// ParsePKCS8PrivateKey parses an unencrypted private key in PKCS #8, ASN.1 DER form.
//
// It returns a *[rsa.PrivateKey], an *[ecdsa.PrivateKey], an [ed25519.PrivateKey] (not
// a pointer), or an *[ecdh.PrivateKey] (for X25519). More types might be supported
// in the future.
//
// This kind of key is commonly encoded in PEM blocks of type "PRIVATE KEY".
//
// Before Go 1.24, the CRT parameters of RSA keys were ignored and recomputed.
// To restore the old behavior, use the GODEBUG=x509rsacrt=0 environment variable.
func ParsePKCS8PrivateKey(der []byte) (key any, err pkerr.Kerror) {
	var privKey keys.Pkcs8
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		if _, err := asn1.Unmarshal(der, &keys.EcPrivateKey{}); err == nil {
			return nil, pkerr.NewErrFailToParsePrivateKeyGotoECP()
		}
		if _, err := asn1.Unmarshal(der, &keys.Pkcs1PrivateKey{}); err == nil {
			return nil, pkerr.NewErrFailToParsePrivateKeyGotoPKCS1()
		}
		return nil, err
	}

	switch {
	case privKey.Algo.Algorithm.Equal(pkix.OidPublicKeyRSA):
		key, err = pkcs1.ParsePKCS1PrivateKey(privKey.PrivateKey)
		if err != nil {
			return nil, pkerr.NewErrParsingRSAPrivateKeyInPKCS8(err)
		}
		return key, nil

	case privKey.Algo.Algorithm.Equal(pkix.OidPublicKeyECDSA):
		bytes := privKey.Algo.Parameters.FullBytes
		namedCurveOID := new(asn1.ObjectIdentifier)
		if _, err := asn1.Unmarshal(bytes, namedCurveOID); err != nil {
			namedCurveOID = nil
		}
		key, err = keys.ParseECPrivateKey(namedCurveOID, privKey.PrivateKey)
		if err != nil {
			return nil, err
		}
		return key, nil

	case privKey.Algo.Algorithm.Equal(pkix.OidPublicKeyEd25519):
		if l := len(privKey.Algo.Parameters.FullBytes); l != 0 {
			return nil, pkerr.NewErrInvalidEd25519Params()
		}
		var curvePrivateKey []byte
		if _, err := asn1.Unmarshal(privKey.PrivateKey, &curvePrivateKey); err != nil {
			return nil, pkerr.NewErrInvalidEd25519PrivateKey(err)
		}
		if l := len(curvePrivateKey); l != ed25519.SeedSize {
			return nil, pkerr.NewErrInvalidEd25519PrivateKeylen(l)
		}
		return ed25519.NewKeyFromSeed(curvePrivateKey), nil

	case privKey.Algo.Algorithm.Equal(pkix.OidPublicKeyX25519):
		if l := len(privKey.Algo.Parameters.FullBytes); l != 0 {
			return nil, pkerr.NewErrInvalidX25519Params()
		}
		var curvePrivateKey []byte
		if _, err := asn1.Unmarshal(privKey.PrivateKey, &curvePrivateKey); err != nil {
			return nil, pkerr.NewErrInvalidX25519PrivateKey(err)
		}
		key, errNative := ecdh.X25519().NewPrivateKey(curvePrivateKey)
		return key, pkerr.NewErrNative(errNative)

	default:
		return nil, pkerr.NewErrPKCS8WrappingUnknownAlgorithm(privKey.Algo.Algorithm)
	}
}

func ParsePKCS8EncryptedPrivateKey(der, password []byte) (key any, err pkerr.Kerror) {
	// Use the password provided to decrypt the private key
	var privKey encryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, pkerr.NewErrOnlyPKCS5v20()
	}

	var decryptedData []byte
	decryptedData, err = pkcs5.ParseEncryptedPKCS5(privKey.EncryptionAlgorithm, privKey.EncryptedData, password)
	if err != nil {
		return
	}

	key, err = ParsePKCS8PrivateKey(decryptedData)
	return
}

// MarshalPKCS8PrivateKey converts a private key to PKCS #8, ASN.1 DER form.
//
// The following key types are currently supported: *[rsa.PrivateKey],
// *[ecdsa.PrivateKey], [ed25519.PrivateKey] (not a pointer), and *[ecdh.PrivateKey].
// Unsupported key types result in an error.
//
// This kind of key is commonly encoded in PEM blocks of type "PRIVATE KEY".
//
// MarshalPKCS8PrivateKey runs [rsa.PrivateKey.Precompute] on RSA keys.
func MarshalPKCS8PrivateKey(key any) ([]byte, pkerr.Kerror) {
	var privKey keys.Pkcs8

	switch k := key.(type) {
	case *rsa.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm:  pkix.OidPublicKeyRSA,
			Parameters: asn1.NullRawValue,
		}
		k.Precompute()
		if err := k.Validate(); err != nil {
			return nil, pkerr.NewErrNative(err)
		}
		privKey.PrivateKey = pkcs1.MarshalPKCS1PrivateKey(k)

	case *ecdsa.PrivateKey:
		oid, ok := pkix.OidFromNamedCurve(k.Curve)
		if !ok {
			return nil, pkerr.NewErrUnknownCurveMarshalPKCS8()
		}
		oidBytes, err := asn1.Marshal(oid)
		if err != nil {
			return nil, pkerr.NewErrMarshalCurveOid(err)
		}
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: pkix.OidPublicKeyECDSA,
			Parameters: asn1.RawValue{
				FullBytes: oidBytes,
			},
		}
		if privKey.PrivateKey, err = keys.MarshalECPrivateKeyWithOID(k, nil); err != nil {
			return nil, pkerr.NewErrMarshalPKSC8PrivateKey("EC", err)
		}

	case ed25519.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: pkix.OidPublicKeyEd25519,
		}
		curvePrivateKey, err := asn1.Marshal(k.Seed())
		if err != nil {
			return nil, pkerr.NewErrMarshalPKSC8PrivateKey("Ed25519", err)
		}
		privKey.PrivateKey = curvePrivateKey

	case *ecdh.PrivateKey:
		if k.Curve() == ecdh.X25519() {
			privKey.Algo = pkix.AlgorithmIdentifier{
				Algorithm: pkix.OidPublicKeyX25519,
			}
			var err error
			if privKey.PrivateKey, err = asn1.Marshal(k.Bytes()); err != nil {
				return nil, pkerr.NewErrMarshalPKSC8PrivateKey("X25519", err)
			}
		} else {
			oid, ok := pkix.OidFromECDHCurve(k.Curve())
			if !ok {
				return nil, pkerr.NewErrMarshalPKSC8Curve()
			}
			oidBytes, err := asn1.Marshal(oid)
			if err != nil {
				return nil, pkerr.NewErrMarshalCurveOid(err)
			}
			privKey.Algo = pkix.AlgorithmIdentifier{
				Algorithm: pkix.OidPublicKeyECDSA,
				Parameters: asn1.RawValue{
					FullBytes: oidBytes,
				},
			}
			if privKey.PrivateKey, err = keys.MarshalECDHPrivateKey(k); err != nil {
				return nil, pkerr.NewErrMarshalPKCS8ECPrivateKey(err)
			}
		}

	default:
		return nil, pkerr.NewErrMarshalPKCS8KeyType(key)
	}

	return asn1.Marshal(privKey)
}

// MarshalPKCS8EncryptedPrivateKey is the same as MarshalPKCS8PrivateKey but encrypt the key using PKCS5 options
func MarshalPKCS8EncryptedPrivateKey(key any, password []byte, options ...*pkcs5.Opts) ([]byte, pkerr.Kerror) {
	data, err := MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	encryptionAlgorithm, encryptedKey, err := pkcs5.MarshalEncryptedPKCS5(data, password, options...)
	if err != nil {
		return nil, err
	}

	encryptedPkey := encryptedPrivateKeyInfo{
		EncryptionAlgorithm: *encryptionAlgorithm,
		EncryptedData:       encryptedKey,
	}

	return asn1.Marshal(encryptedPkey)
}
