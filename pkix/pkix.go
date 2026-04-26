// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package pkix contains shared, low level structures used for ASN.1 parsing
// and serialization of X.509 certificates, CRL and OCSP.
package pkix

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"slices"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/pkerr"
)

// Extension represents the ASN.1 structure of the same name. See RFC
// 5280, section 4.2.
type Extension struct {
	Id       asn1.ObjectIdentifier
	Critical bool `asn1:"optional"`
	Value    []byte
}

// AlgorithmIdentifier represents the ASN.1 structure of the same name. See RFC
// 5280, section 4.1.1.2.
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// pssParameters reflects the parameters in an AlgorithmIdentifier that
// specifies RSA PSS. See RFC 3447, Appendix A.2.3.
type pssParameters struct {
	// The following three fields are not marked as
	// optional because the default values specify SHA-1,
	// which is no longer suitable for use in signatures.
	Hash         AlgorithmIdentifier `asn1:"explicit,tag:0"`
	MGF          AlgorithmIdentifier `asn1:"explicit,tag:1"`
	SaltLength   int                 `asn1:"explicit,tag:2"`
	TrailerField int                 `asn1:"optional,explicit,tag:3,default:1"`
}

func (ai AlgorithmIdentifier) GetSignatureAlgorithm() SignatureAlgorithm {
	if ai.Algorithm.Equal(OidSignatureEd25519) {
		// RFC 8410, Section 3
		// > For all of the OIDs, the parameters MUST be absent.
		if len(ai.Parameters.FullBytes) != 0 {
			return UnknownSignatureAlgorithm
		}
	}

	if !ai.Algorithm.Equal(OidSignatureRSAPSS) {
		return GetSignatureAlgorithmFromOID(ai.Algorithm)
	}

	// RSA PSS is special because it encodes important parameters
	// in the Parameters.

	var params pssParameters
	if _, err := asn1.Unmarshal(ai.Parameters.FullBytes, &params); err != nil {
		return UnknownSignatureAlgorithm
	}

	var mgf1HashFunc AlgorithmIdentifier
	if _, err := asn1.Unmarshal(params.MGF.Parameters.FullBytes, &mgf1HashFunc); err != nil {
		return UnknownSignatureAlgorithm
	}

	// PSS is greatly overburdened with options. This code forces them into
	// three buckets by requiring that the MGF1 hash function always match the
	// message hash function (as recommended in RFC 3447, Section 8.1), that the
	// salt length matches the hash length, and that the trailer field has the
	// default value.
	if (len(params.Hash.Parameters.FullBytes) != 0 && !bytes.Equal(params.Hash.Parameters.FullBytes, asn1.NullBytes)) ||
		!params.MGF.Algorithm.Equal(OidMGF1) ||
		!mgf1HashFunc.Algorithm.Equal(params.Hash.Algorithm) ||
		(len(mgf1HashFunc.Parameters.FullBytes) != 0 && !bytes.Equal(mgf1HashFunc.Parameters.FullBytes, asn1.NullBytes)) ||
		params.TrailerField != 1 {
		return UnknownSignatureAlgorithm
	}

	switch {
	case params.Hash.Algorithm.Equal(OidSHA256) && params.SaltLength == 32:
		return RSAPSSWithSHA256
	case params.Hash.Algorithm.Equal(OidSHA384) && params.SaltLength == 48:
		return RSAPSSWithSHA384
	case params.Hash.Algorithm.Equal(OidSHA512) && params.SaltLength == 64:
		return RSAPSSWithSHA512
	}

	return UnknownSignatureAlgorithm
}

func GetSignatureAlgorithm(digestEncryption, digest AlgorithmIdentifier) (SignatureAlgorithm, pkerr.Kerror) {
	switch {
	case digestEncryption.Algorithm.Equal(OidSignatureECDSAWithSHA256):
		return ECDSAWithSHA256, nil
	case digestEncryption.Algorithm.Equal(OidSignatureECDSAWithSHA384):
		return ECDSAWithSHA384, nil
	case digestEncryption.Algorithm.Equal(OidSignatureECDSAWithSHA512):
		return ECDSAWithSHA512, nil
	case digestEncryption.Algorithm.Equal(OIDEncryptionAlgorithmRSA),
		digestEncryption.Algorithm.Equal(OIDSignatureAlgorithmRSASHA256),
		digestEncryption.Algorithm.Equal(OIDSignatureAlgorithmRSASHA384),
		digestEncryption.Algorithm.Equal(OIDSignatureAlgorithmRSASHA512):
		switch {
		case digest.Algorithm.Equal(oidDigestAlgorithmSHA1):
			return RSAWithSHA1, nil
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA256):
			return RSAWithSHA256, nil
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA384):
			return RSAWithSHA384, nil
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA512):
			return RSAWithSHA512, nil
		default:
			return -1, pkerr.NewErrUnsupportedDigestForEcryptionAlgorithm(
				digest.Algorithm.String(), digestEncryption.Algorithm.String())
		}
	case digestEncryption.Algorithm.Equal(OIDSignatureAlgorithmECDSAP256),
		digestEncryption.Algorithm.Equal(OIDSignatureAlgorithmECDSAP384),
		digestEncryption.Algorithm.Equal(OIDSignatureAlgorithmECDSAP521):
		switch {
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA256):
			return ECDSAWithSHA256, nil
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA384):
			return ECDSAWithSHA384, nil
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA512):
			return ECDSAWithSHA512, nil
		default:
			return -1, pkerr.NewErrUnsupportedDigestForEcryptionAlgorithm(
				digest.Algorithm.String(), digestEncryption.Algorithm.String())
		}
	default:
		return -1, pkerr.NewErrUnsupportedAlgorithm(
			digestEncryption.Algorithm.String())
	}
}

func GetHashForOID(oid asn1.ObjectIdentifier) (crypto.Hash, pkerr.Kerror) {
	switch {
	case oid.Equal(oidDigestAlgorithmSHA1):
		return crypto.SHA1, nil
	case oid.Equal(OIDDigestAlgorithmSHA256), oid.Equal(OIDDigestAlgorithmECDSASHA256):
		return crypto.SHA256, nil
	case oid.Equal(OIDDigestAlgorithmSHA384), oid.Equal(OIDDigestAlgorithmECDSASHA384):
		return crypto.SHA384, nil
	case oid.Equal(OIDDigestAlgorithmSHA512), oid.Equal(OIDDigestAlgorithmECDSASHA512):
		return crypto.SHA512, nil
	}
	return crypto.Hash(0), pkerr.NewErrCannotDecryptData()
}

// getOIDForEncryptionAlgorithm takes the private key type of the signer and
// the OID of a digest algorithm to return the appropriate signerInfo.DigestEncryptionAlgorithm
func GetEncryptionAlgorithmOID(pkey crypto.PrivateKey, OIDDigestAlg asn1.ObjectIdentifier) (asn1.ObjectIdentifier, pkerr.Kerror) {

	switch pkey.(type) {
	case *rsa.PrivateKey:
		switch {
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA256):
			return OIDSignatureAlgorithmRSASHA256, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA384):
			return OIDSignatureAlgorithmRSASHA384, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA512):
			return OIDSignatureAlgorithmRSASHA512, nil
		}
	case *ecdsa.PrivateKey:
		switch {
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA256):
			return OIDDigestAlgorithmECDSASHA256, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA384):
			return OIDDigestAlgorithmECDSASHA384, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA512):
			return OIDDigestAlgorithmECDSASHA512, nil
		}
	}
	return nil, pkerr.NewErrConvertEncryptionAlgorithmToOid(pkey)

}

type AttributeTypeAndValueSET struct {
	Type  asn1.ObjectIdentifier
	Value [][]AttributeTypeAndValue `asn1:"set"`
}

type OtherName struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

func (o *OtherName) Set(value any, oid ...int) (err pkerr.Kerror) {
	if len(oid) < 4 {
		return pkerr.NewErrOIDInvalid()
	}
	o.Type = asn1.ObjectIdentifier(oid)
	var val []byte
	val, err = asn1.Marshal(value)
	if err == nil {
		o.Value = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: val}
	}
	return
}

// The RegiterID in x509 SAN extension is an alias of asn1.ObjectIdentifier with a different Tag
// Therefore, the methods are wrapped
type RegisterID asn1.ObjectIdentifier

// Equal reports whether oi and other represent the same identifier.
func (rid RegisterID) Equal(other RegisterID) bool {
	return slices.Equal(rid, other)
}

func (rid RegisterID) String() string {
	return asn1.ObjectIdentifier(rid).String()
}

func (rid *RegisterID) Set(value ...int) error {
	if len(value) < 4 {
		return pkerr.NewErrOIDInvalid()
	}
	*rid = value
	return nil
}
