// Copyright 2015, 2018, 2019 Opsmate, Inc. All rights reserved.
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/pkcs5"
	"github.com/pduveau/gocert/pkix"
)

type macData struct {
	Mac        digestInfo
	MacSalt    []byte
	Iterations int `asn1:"optional,default:1"`
}

// from PKCS#7:
type digestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

var (
	oidSHA1   = asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26})
	oidSHA256 = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 1})
	oidSHA512 = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 3})
	oidPBMAC1 = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 5, 14})
)

// doPBMAC1 handles PBMAC1 MAC computation using parameters from Algorithm.Parameters
// PBMAC1 (RFC 8018) uses PBKDF2 for key derivation and supports various HMAC algorithms.
// Unlike traditional PKCS#12 MAC algorithms, PBMAC1 gets all its parameters from
// the Algorithm.Parameters field, ignoring macData.MacSalt and macData.Iterations.
func doPBMAC1(algorithm pkix.AlgorithmIdentifier, message, password []byte) ([]byte, error) {
	params, err := pkcs5.ParsePBES2Params(algorithm.Parameters.FullBytes)
	if err != nil {
		return nil, err
	}

	// Only PBKDF2 is supported as KDF
	if !params.KeyDerivationFunc.Algorithm.Equal(pkcs5.OidPKCS5PBKDF2) {
		return nil, fmt.Errorf("PKCS12: PBMAC1 KDF algorithm %s is not supported", params.KeyDerivationFunc.Algorithm.String())
	}

	kdfParams, err := pkcs5.ParseKeyDerivationFunc(params.KeyDerivationFunc)
	if err != nil {
		return nil, err
	}

	key, err := kdfParams.DeriveKey(password, kdfParams.GetKeyLength())
	if err != nil {
		return nil, err
	}

	// Determine MAC algorithm
	var hFn func() hash.Hash
	switch {
	case params.EncryptionScheme.Algorithm.Equal(pkcs5.OidHMACWithSHA1.ToAsn1()):
		hFn = sha1.New
	case params.EncryptionScheme.Algorithm.Equal(pkcs5.OidHMACWithSHA256.ToAsn1()):
		hFn = sha256.New
	case params.EncryptionScheme.Algorithm.Equal(pkcs5.OidHMACWithSHA512.ToAsn1()):
		hFn = sha512.New
	default:
		return nil, NotImplementedError("PKCS12: PBMAC1 MAC algorithm " + params.EncryptionScheme.Algorithm.String() + " is not supported")
	}

	// Compute HMAC
	mac := hmac.New(hFn, key)
	mac.Write(message)
	return mac.Sum(nil), nil
}

func doMac(macData *macData, message, password []byte) ([]byte, error) {
	// Handle PBMAC1 separately - it uses its own parameters structure from Algorithm.Parameters
	// and ignores macData.MacSalt and macData.Iterations fields
	if macData.Mac.Algorithm.Algorithm.Equal(oidPBMAC1) {
		// PBMAC1 expects UTF-8 passwords (for compatibility; see Erratum 7974), but
		// PKCS#12 passwords are BMP strings, so we convert the BMP string back to UTF-8
		originalPassword, err := decodeBMPString(password)
		if err != nil {
			return nil, err
		}
		utf8Password := []byte(originalPassword)
		return doPBMAC1(macData.Mac.Algorithm, message, utf8Password)
	}

	var hFn func() hash.Hash
	var key []byte
	switch {
	case macData.Mac.Algorithm.Algorithm.Equal(oidSHA1):
		hFn = sha1.New
		key = pbkdf(sha1Sum, 20, 64, macData.MacSalt, password, macData.Iterations, 3, 20)
	case macData.Mac.Algorithm.Algorithm.Equal(oidSHA256):
		hFn = sha256.New
		key = pbkdf(sha256Sum, 32, 64, macData.MacSalt, password, macData.Iterations, 3, 32)
	case macData.Mac.Algorithm.Algorithm.Equal(oidSHA512):
		hFn = sha512.New
		key = pbkdf(sha512Sum, 64, 128, macData.MacSalt, password, macData.Iterations, 3, 64)
	default:
		return nil, NotImplementedError("pkcs12: MAC digest algorithm not supported: " + macData.Mac.Algorithm.Algorithm.String())
	}

	mac := hmac.New(hFn, key)
	mac.Write(message)
	return mac.Sum(nil), nil
}

func verifyMac(macData *macData, message, password []byte) error {
	expectedMAC, err := doMac(macData, message, password)
	if err != nil {
		return err
	}
	if !hmac.Equal(macData.Mac.Digest, expectedMAC) {
		return ErrIncorrectPassword
	}
	return nil
}

func computeMac(macData *macData, message, password []byte) error {
	digest, err := doMac(macData, message, password)
	if err != nil {
		return err
	}
	macData.Mac.Digest = digest
	return nil
}
