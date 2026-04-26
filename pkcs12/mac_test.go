// Copyright 2015, 2018, 2019 Opsmate, Inc. All rights reserved.
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"bytes"
	"crypto/hmac"
	"fmt"
	"testing"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/pkcs5"
	"github.com/pduveau/gocert/pkerr"
	"github.com/pduveau/gocert/pkix"
)

func TestVerifyMac(t *testing.T) {
	td := macData{
		Mac: digestInfo{
			Digest: []byte{0x18, 0x20, 0x3d, 0xff, 0x1e, 0x16, 0xf4, 0x92, 0xf2, 0xaf, 0xc8, 0x91, 0xa9, 0xba, 0xd6, 0xca, 0x9d, 0xee, 0x51, 0x93},
		},
		MacSalt:    []byte{1, 2, 3, 4, 5, 6, 7, 8},
		Iterations: 2048,
	}

	message := []byte{11, 12, 13, 14, 15}
	password, _ := bmpStringZeroTerminated("")

	td.Mac.Algorithm.Algorithm = asn1.ObjectIdentifier([]int{1, 2, 3})
	err := verifyMac(&td, message, password)
	if _, ok := err.(*pkerr.ErrMacDigestUnsupportedAlgorithm); !ok {
		t.Errorf("err: %v", err)
	}

	td.Mac.Algorithm.Algorithm = asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26})
	err = verifyMac(&td, message, password)
	if _, ok := err.(*pkerr.ErrIncorrectPassword); !ok {
		t.Errorf("Expected incorrect decryption password, got err: %v", err)
	}

	password, _ = bmpStringZeroTerminated("Sesame open")
	err = verifyMac(&td, message, password)
	if err != nil {
		t.Errorf("err: %v", err)
	}

}

func TestDoMac(t *testing.T) {
	var err error
	td := macData{
		MacSalt:    []byte{1, 2, 3, 4, 5, 6, 7, 8},
		Iterations: 2048,
	}

	message := []byte{11, 12, 13, 14, 15}
	password, _ := bmpStringZeroTerminated("Sesame open")

	td.Mac.Algorithm.Algorithm = asn1.ObjectIdentifier([]int{1, 2, 3})
	_, err = doMac(&td, message, password)
	if _, ok := err.(*pkerr.ErrMacDigestUnsupportedAlgorithm); !ok {
		t.Errorf("err: %v", err)
	} else {
		fmt.Printf("Valide Error %s", err.Error())
	}

	td.Mac.Algorithm.Algorithm = asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26})
	td.Mac.Digest, err = doMac(&td, message, password)
	if err != nil {
		t.Errorf("err: %v", err)
	}

	expectedDigest := []byte{0x18, 0x20, 0x3d, 0xff, 0x1e, 0x16, 0xf4, 0x92, 0xf2, 0xaf, 0xc8, 0x91, 0xa9, 0xba, 0xd6, 0xca, 0x9d, 0xee, 0x51, 0x93}

	if !bytes.Equal(td.Mac.Digest, expectedDigest) {
		t.Errorf("Computed incorrect MAC; expected MAC to be '%d' but got '%d'", expectedDigest, td.Mac.Digest)
	}

}

func TestPBMAC1(t *testing.T) {
	opts5 := pkcs5.NewDefaultPBMAC1Opts()
	opts5.KDFParams.SetIterations(1000)
	opts5.KDFParams.SetKeyLength(32)
	opts5.KDFParams.SetSalt([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	opts5.KDFParams.SetHmacOID(pkix.OidHMACWithSHA512)

	ai, _, pbes2, err := pkcs5.MakePBES2(opts5)
	if err != nil {
		t.Fatalf("Failed to marshal PBMAC1 params: %v", err)
	}

	// Create macData with PBMAC1 algorithm
	td := macData{
		Mac: digestInfo{
			Algorithm: *ai,
		},
		// MacSalt and Iterations should be ignored for PBMAC1
		MacSalt:    []byte{9, 10, 11, 12},
		Iterations: 999,
	}

	message := []byte{11, 12, 13, 14, 15}
	password, err := bmpStringZeroTerminated("test-password")
	if err != nil {
		t.Fatalf("Failed to encode password to BMP string: %v", err)
	}

	// Test MAC computation
	td.Mac.Digest, err = doPBMAC1(td.Mac.Algorithm, message, password)
	if err != nil {
		t.Errorf("Failed to compute PBMAC1: %v", err)
	}

	// Verify that MAC was computed
	if len(td.Mac.Digest) == 0 {
		t.Error("No MAC digest was computed")
	}

	if !bytes.Equal(td.Mac.Digest, []byte{0xff, 0x5c, 0x9f, 0x02, 0x8c, 0xdc, 0x21, 0xa1, 0xa1, 0x17, 0x12, 0xa8, 0xa0, 0xe4, 0xd4, 0x2d, 0xf8, 0xf6, 0x8b, 0xc5, 0xbd, 0xec, 0xe7, 0xde, 0xcf, 0xd9, 0x2e, 0x0c, 0x65, 0xcd, 0x1c, 0x6f}) {
		t.Error("Wrong MAC digest was computed")
	}

	utf8Password, err := decodeBMPString(password)
	if err != nil {
		t.Error("Password to utf8 error")
	}

	hFn, key, err := pbes2.PKCS12MacAlgorithmAndKey([]byte(utf8Password))
	if err != nil {
		t.Error("Digest func and key error")
	}

	// Compute HMAC
	mac := hmac.New(hFn, key)
	mac.Write(message)
	td.Mac.Digest = mac.Sum(nil)

	if !bytes.Equal(td.Mac.Digest, []byte{0xff, 0x5c, 0x9f, 0x02, 0x8c, 0xdc, 0x21, 0xa1, 0xa1, 0x17, 0x12, 0xa8, 0xa0, 0xe4, 0xd4, 0x2d, 0xf8, 0xf6, 0x8b, 0xc5, 0xbd, 0xec, 0xe7, 0xde, 0xcf, 0xd9, 0x2e, 0x0c, 0x65, 0xcd, 0x1c, 0x6f}) {
		t.Error("Wrong MAC digest was computed")
	}

	// Test MAC verification
	err = verifyMac(&td, message, password)
	if err != nil {
		t.Errorf("Failed to verify PBMAC1: %v", err)
	}

	// Test with wrong password
	wrongPassword, err := bmpStringZeroTerminated("wrong-password")
	if err != nil {
		t.Fatalf("Failed to encode wrong password to BMP string: %v", err)
	}
	err = verifyMac(&td, message, wrongPassword)
	if _, ok := err.(*pkerr.ErrIncorrectPassword); !ok {
		t.Errorf("Expected ErrIncorrectPassword, got: %v", err)
	}
}
