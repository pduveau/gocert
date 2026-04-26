// Copyright 2015, 2018, 2019 Opsmate, Inc. All rights reserved.
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"crypto/hmac"
	"hash"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/pkcs5"
	"github.com/pduveau/gocert/pkerr"
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
func doPBMAC1(algorithm pkix.AlgorithmIdentifier, message, password []byte) ([]byte, pkerr.Kerror) {
	params, err := pkcs5.ParsePBES2Params(algorithm.Parameters.FullBytes)
	if err != nil {
		return nil, err
	}

	var originalPassword string
	originalPassword, err = decodeBMPString(password)
	if err != nil {
		return nil, err
	}

	// Determine MAC algorithm
	hFn, key, err := params.PKCS12MacAlgorithmAndKey([]byte(originalPassword))
	if err != nil {
		return nil, err
	}

	// Compute HMAC
	mac := hmac.New(hFn, key)
	mac.Write(message)
	return mac.Sum(nil), nil
}

func doMac(macData *macData, message, password []byte) (sum []byte, err pkerr.Kerror) {
	// Handle PBMAC1 separately - it uses its own parameters structure from Algorithm.Parameters
	// and ignores macData.MacSalt and macData.Iterations fields

	var hFn func() hash.Hash
	var key []byte

	hFn, key, err = pkdkfKeyAndDigest(macData.Mac.Algorithm.Algorithm, macData.MacSalt, password, macData.Iterations)

	if err == nil {
		mac := hmac.New(hFn, key)
		mac.Write(message)
		sum = mac.Sum(nil)
	}

	return
}

func verifyMac(macData *macData, message, password []byte) (err pkerr.Kerror) {
	var digest []byte
	if macData.Mac.Algorithm.Algorithm.Equal(oidPBMAC1) {
		// PBMAC1 expects UTF-8 passwords (for compatibility; see Erratum 7974), but
		// PKCS#12 passwords are BMP strings, so we convert the BMP string back to UTF-8
		digest, err = doPBMAC1(macData.Mac.Algorithm, message, password)
	} else {
		digest, err = doMac(macData, message, password)
	}
	if err == nil {
		if !hmac.Equal(macData.Mac.Digest, digest) {
			return pkerr.NewErrIncorrectPassword()
		}
	}
	return
}
