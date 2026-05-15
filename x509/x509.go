// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package x509 implements a subset of the X.509 standard.
//
// It allows parsing and generating certificates, certificate signing
// requests, certificate revocation lists, and encoded public and private keys.
// It provides a certificate verifier, complete with a chain builder.
//
// The package targets the X.509 technical profile defined by the IETF (RFC
// 2459/3280/5280), and as further restricted by the CA/Browser Forum Baseline
// Requirements. There is minimal support for features outside of these
// profiles, as the primary goal of the package is to provide compatibility
// with the publicly trusted TLS certificate ecosystem and its policies and
// constraints.
//
// On macOS and Windows, certificate verification is handled by system APIs, but
// the package aims to apply consistent validation rules across operating
// systems.
package x509

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io"
	"math/big"
	"net"
	"net/url"
	"time"

	// Explicitly import these for their crypto.RegisterHash init side-effects.
	// Keep these as blank imports, even if they're imported above.
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/internal/pkixstring"
	"github.com/pduveau/gocert/keys"
	"github.com/pduveau/gocert/pkerr"
	"github.com/pduveau/gocert/pkix"
)

// pkixPublicKey reflects a PKIX public key structure. See SubjectPublicKeyInfo
// in RFC 3280.
type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

// ParsePKIXPublicKey parses a public key in PKIX, ASN.1 DER form. The encoded
// public key is a SubjectPublicKeyInfo structure (see RFC 5280, Section 4.1).
//
// It returns a *[rsa.PublicKey], *[dsa.PublicKey], *[ecdsa.PublicKey],
// [ed25519.PublicKey] (not a pointer), or *[ecdh.PublicKey] (for X25519).
// More types might be supported in the future.
//
// This kind of key is commonly encoded in PEM blocks of type "PUBLIC KEY".
func ParsePKIXPublicKey(derBytes []byte) (pub any, err pkerr.Kerror) {
	var pki keys.PublicKeyInfo
	if rest, err := asn1.Unmarshal(derBytes, &pki); err != nil {
		if _, err := asn1.Unmarshal(derBytes, &keys.Pkcs1PublicKey{}); err == nil {
			return nil, pkerr.NewErrFailToParsePublicKeyGotoPKCS1()
		}
		return nil, err
	} else if len(rest) != 0 {
		return nil, pkerr.NewErrASN1TrailingData("public-key")
	}
	return pki.ParsePublicKey()
}

// MarshalPKIXPublicKey converts a public key to PKIX, ASN.1 DER form.
// The encoded public key is a SubjectPublicKeyInfo structure
// (see RFC 5280, Section 4.1).
//
// The following key types are currently supported: *[rsa.PublicKey],
// *[ecdsa.PublicKey], [ed25519.PublicKey] (not a pointer), and *[ecdh.PublicKey].
// Unsupported key types result in an pkerr.Kerror.
//
// This kind of key is commonly encoded in PEM blocks of type "PUBLIC KEY".
func MarshalPKIXPublicKey(pub any) ([]byte, pkerr.Kerror) {
	var publicKeyBytes []byte
	var publicKeyAlgorithm pkix.AlgorithmIdentifier
	var err pkerr.Kerror

	if publicKeyBytes, publicKeyAlgorithm, err = keys.MarshalPublicKey(pub); err != nil {
		return nil, err
	}

	pkix := pkixPublicKey{
		Algo: publicKeyAlgorithm,
		BitString: asn1.BitString{
			Bytes:     publicKeyBytes,
			BitLength: 8 * len(publicKeyBytes),
		},
	}

	ret, _ := asn1.Marshal(pkix)
	return ret, nil
}

// These structures reflect the ASN.1 structure of X.509 certificates.:

type certificate struct {
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          keys.PublicKeyInfo
	UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"omitempty,optional,explicit,tag:3"`
}

type validity struct {
	NotBefore, NotAfter time.Time
}

// RFC 5280,  4.2.1.1
type authKeyId struct {
	Id []byte `asn1:"optional,tag:0"`
}

// KeyUsage represents the set of actions that are valid for a given key. It's
// a bitmap of the KeyUsage* constants.
type KeyUsage int

//go:generate stringer -linecomment -type=KeyUsage,ExtKeyUsage -output=x509_string.go

const (
	KeyUsageDigitalSignature  KeyUsage = 1 << iota // digitalSignature
	KeyUsageContentCommitment                      // contentCommitment
	KeyUsageKeyEncipherment                        // keyEncipherment
	KeyUsageDataEncipherment                       // dataEncipherment
	KeyUsageKeyAgreement                           // keyAgreement
	KeyUsageCertSign                               // keyCertSign
	KeyUsageCRLSign                                // cRLSign
	KeyUsageEncipherOnly                           // encipherOnly
	KeyUsageDecipherOnly                           // decipherOnly
)

// RFC 5280, 4.2.1.12  Extended Key Usage
//
//	anyExtendedKeyUsage OBJECT IDENTIFIER ::= { id-ce-extKeyUsage 0 }
//
//	id-kp OBJECT IDENTIFIER ::= { id-pkix 3 }
//
//	id-kp-serverAuth             OBJECT IDENTIFIER ::= { id-kp 1 }
//	id-kp-clientAuth             OBJECT IDENTIFIER ::= { id-kp 2 }
//	id-kp-codeSigning            OBJECT IDENTIFIER ::= { id-kp 3 }
//	id-kp-emailProtection        OBJECT IDENTIFIER ::= { id-kp 4 }
//	id-kp-timeStamping           OBJECT IDENTIFIER ::= { id-kp 8 }
//	id-kp-OCSPSigning            OBJECT IDENTIFIER ::= { id-kp 9 }
//
// https://www.iana.org/assignments/smi-numbers/smi-numbers.xhtml#smi-numbers-1.3.6.1.5.5.7.3
var (
	oidExtKeyUsageAny                            = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	oidExtKeyUsageServerAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidExtKeyUsageCodeSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	oidExtKeyUsageEmailProtection                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	oidExtKeyUsageIPSECEndSystem                 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
	oidExtKeyUsageIPSECTunnel                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
	oidExtKeyUsageIPSECUser                      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
	oidExtKeyUsageTimeStamping                   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidExtKeyUsageOCSPSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	oidExtKeyUsageMicrosoftServerGatedCrypto     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}
	oidExtKeyUsageNetscapeServerGatedCrypto      = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}
	oidExtKeyUsageMicrosoftCommercialCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}
	oidExtKeyUsageMicrosoftKernelCodeSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}
)

// ExtKeyUsage represents an extended set of actions that are valid for a given key.
// Each of the ExtKeyUsage* constants define a unique action.
type ExtKeyUsage int

const (
	ExtKeyUsageAny                            ExtKeyUsage = iota // anyExtendedKeyUsage
	ExtKeyUsageServerAuth                                        // serverAuth
	ExtKeyUsageClientAuth                                        // clientAuth
	ExtKeyUsageCodeSigning                                       // codeSigning
	ExtKeyUsageEmailProtection                                   // emailProtection
	ExtKeyUsageIPSECEndSystem                                    // ipsecEndSystem
	ExtKeyUsageIPSECTunnel                                       // ipsecTunnel
	ExtKeyUsageIPSECUser                                         // ipsecUser
	ExtKeyUsageTimeStamping                                      // timeStamping
	ExtKeyUsageOCSPSigning                                       // OCSPSigning
	ExtKeyUsageMicrosoftServerGatedCrypto                        // msSGC
	ExtKeyUsageNetscapeServerGatedCrypto                         // nsSGC
	ExtKeyUsageMicrosoftCommercialCodeSigning                    // msCodeCom
	ExtKeyUsageMicrosoftKernelCodeSigning                        // msKernelCode
)

// extKeyUsageOIDs contains the mapping between an ExtKeyUsage and its OID.
var extKeyUsageOIDs = []struct {
	extKeyUsage ExtKeyUsage
	oid         asn1.ObjectIdentifier
}{
	{ExtKeyUsageAny, oidExtKeyUsageAny},
	{ExtKeyUsageServerAuth, oidExtKeyUsageServerAuth},
	{ExtKeyUsageClientAuth, oidExtKeyUsageClientAuth},
	{ExtKeyUsageCodeSigning, oidExtKeyUsageCodeSigning},
	{ExtKeyUsageEmailProtection, oidExtKeyUsageEmailProtection},
	{ExtKeyUsageIPSECEndSystem, oidExtKeyUsageIPSECEndSystem},
	{ExtKeyUsageIPSECTunnel, oidExtKeyUsageIPSECTunnel},
	{ExtKeyUsageIPSECUser, oidExtKeyUsageIPSECUser},
	{ExtKeyUsageTimeStamping, oidExtKeyUsageTimeStamping},
	{ExtKeyUsageOCSPSigning, oidExtKeyUsageOCSPSigning},
	{ExtKeyUsageMicrosoftServerGatedCrypto, oidExtKeyUsageMicrosoftServerGatedCrypto},
	{ExtKeyUsageNetscapeServerGatedCrypto, oidExtKeyUsageNetscapeServerGatedCrypto},
	{ExtKeyUsageMicrosoftCommercialCodeSigning, oidExtKeyUsageMicrosoftCommercialCodeSigning},
	{ExtKeyUsageMicrosoftKernelCodeSigning, oidExtKeyUsageMicrosoftKernelCodeSigning},
}

func extKeyUsageFromOID(oid asn1.ObjectIdentifier) (eku ExtKeyUsage, ok bool) {
	for _, pair := range extKeyUsageOIDs {
		if oid.Equal(pair.oid) {
			return pair.extKeyUsage, true
		}
	}
	return
}

func oidFromExtKeyUsage(eku ExtKeyUsage) (oid asn1.ObjectIdentifier, ok bool) {
	for _, pair := range extKeyUsageOIDs {
		if eku == pair.extKeyUsage {
			return pair.oid, true
		}
	}
	return
}

// OID returns the ASN.1 object identifier of the EKU.
func (eku ExtKeyUsage) OID() OID {
	asn1OID, ok := oidFromExtKeyUsage(eku)
	if !ok {
		panic("x509: internal error: known ExtKeyUsage has no OID")
	}
	oid, err := OIDFromASN1OID(asn1OID)
	if err != nil {
		panic("x509: internal error: known ExtKeyUsage has invalid OID")
	}
	return oid
}

type SubjectAlternativeName struct {
	// Subject Alternate Name values. (Note that these values may not be valid
	// if invalid values were contained within a parsed certificate. For
	// example, an element of DNSNames may not be a valid DNS domain name.)
	OtherNames     []pkix.OtherName
	DNSNames       []string
	EmailAddresses []string
	DirectoryNames []pkix.Name
	IPAddresses    []net.IP
	URIs           []*url.URL
	RegisterIDs    []pkix.RegisterID
}

func NewSAN() *SubjectAlternativeName {
	return &SubjectAlternativeName{}
}

func (san *SubjectAlternativeName) AddOtherName(oid asn1.ObjectIdentifier, value asn1.RawValue) *SubjectAlternativeName {
	san.OtherNames = append(san.OtherNames, pkix.OtherName{Type: oid, Value: value})
	return san
}
func (san *SubjectAlternativeName) AddDirectoryName(in pkix.Name) *SubjectAlternativeName {
	san.DirectoryNames = append(san.DirectoryNames, in)
	return san
}
func (san *SubjectAlternativeName) AddDNSName(in string) *SubjectAlternativeName {
	san.DNSNames = append(san.DNSNames, in)
	return san
}
func (san *SubjectAlternativeName) AddIPAddress(in net.IP) *SubjectAlternativeName {
	san.IPAddresses = append(san.IPAddresses, in)
	return san
}
func (san *SubjectAlternativeName) AddURI(in *url.URL) *SubjectAlternativeName {
	san.URIs = append(san.URIs, in)
	return san
}
func (san *SubjectAlternativeName) AddEmailAddress(in string) *SubjectAlternativeName {
	san.EmailAddresses = append(san.EmailAddresses, in)
	return san
}
func (san *SubjectAlternativeName) AddRegisterIDs(in pkix.RegisterID) *SubjectAlternativeName {
	san.RegisterIDs = append(san.RegisterIDs, in)
	return san
}

// A Certificate represents an X.509 certificate.
type Certificate struct {
	Raw                     []byte // Complete ASN.1 DER content (certificate, signature algorithm and signature).
	RawTBSCertificate       []byte // Certificate part of raw ASN.1 DER content.
	RawSubjectPublicKeyInfo []byte // DER encoded SubjectPublicKeyInfo.
	RawSubject              []byte // DER encoded Subject
	RawIssuer               []byte // DER encoded Issuer

	Signature          []byte
	SignatureAlgorithm pkix.SignatureAlgorithm

	PublicKeyAlgorithm pkix.PublicKeyAlgorithm
	PublicKeyInfo      *keys.PublicKeyInfo
	PublicKey          any

	Version             int
	SerialNumber        *big.Int
	Issuer              pkix.Name
	Subject             pkix.Name
	NotBefore, NotAfter time.Time // Validity bounds.
	KeyUsage            KeyUsage

	// Extensions contains raw X.509 extensions. When parsing certificates,
	// this can be used to extract non-critical extensions that are not
	// parsed by this package. When marshaling certificates, the Extensions
	// field is ignored, see ExtraExtensions.
	Extensions []pkix.Extension

	// ExtraExtensions contains extensions to be copied, raw, into any
	// marshaled certificates. Values override any extensions that would
	// otherwise be produced based on the other fields. The ExtraExtensions
	// field is not populated when parsing certificates, see Extensions.
	ExtraExtensions []pkix.Extension

	// UnhandledCriticalExtensions contains a list of extension IDs that
	// were not (fully) processed when parsing. Verify will fail if this
	// slice is non-empty, unless verification is delegated to an OS
	// library which understands all the critical extensions.
	//
	// Users can access these extensions using Extensions and can remove
	// elements from this slice if they believe that they have been
	// handled.
	UnhandledCriticalExtensions []asn1.ObjectIdentifier

	ExtKeyUsage        []ExtKeyUsage           // Sequence of extended key usages.
	UnknownExtKeyUsage []asn1.ObjectIdentifier // Encountered extended key usages unknown to this package.

	// BasicConstraintsValid indicates whether IsCA, MaxPathLen,
	// and MaxPathLenZero are valid.
	BasicConstraintsValid bool
	IsCA                  bool

	// MaxPathLen and MaxPathLenZero indicate the presence and
	// value of the BasicConstraints' "pathLenConstraint".
	//
	// When parsing a certificate, a positive non-zero MaxPathLen
	// means that the field was specified, -1 means it was unset,
	// and MaxPathLenZero being true mean that the field was
	// explicitly set to zero. The case of MaxPathLen==0 with MaxPathLenZero==false
	// should be treated equivalent to -1 (unset).
	//
	// When generating a certificate, an unset pathLenConstraint
	// can be requested with either MaxPathLen == -1 or using the
	// zero value for both MaxPathLen and MaxPathLenZero.
	MaxPathLen int
	// MaxPathLenZero indicates that BasicConstraintsValid==true
	// and MaxPathLen==0 should be interpreted as an actual
	// maximum path length of zero. Otherwise, that combination is
	// interpreted as MaxPathLen not being set.
	MaxPathLenZero bool

	SubjectKeyId   []byte
	AuthorityKeyId []byte

	// RFC 5280, 4.2.2.1 (Authority Information Access)
	OCSPServer            []string
	IssuingCertificateURL []string

	// SubjectAlternativeName
	San *SubjectAlternativeName

	// Name constraints
	PermittedDNSDomainsCritical bool // if true then the name constraints are marked critical.
	PermittedDNSDomains         []string
	ExcludedDNSDomains          []string
	PermittedIPRanges           []*net.IPNet
	ExcludedIPRanges            []*net.IPNet
	PermittedEmailAddresses     []string
	ExcludedEmailAddresses      []string
	PermittedURIDomains         []string
	ExcludedURIDomains          []string

	// CRL Distribution Points
	CRLDistributionPoints []string

	// Policies contains all policy identifiers included in the certificate.
	// See CreateCertificate for context about how this field and the PolicyIdentifiers field
	// interact.
	// In Go 1.22, encoding/gob cannot handle and ignores this field.
	Policies []OID

	// InhibitAnyPolicy and InhibitAnyPolicyZero indicate the presence and value
	// of the inhibitAnyPolicy extension.
	//
	// The value of InhibitAnyPolicy indicates the number of additional
	// certificates in the path after this certificate that may use the
	// anyPolicy policy OID to indicate a match with any other policy.
	//
	// When parsing a certificate, a positive non-zero InhibitAnyPolicy means
	// that the field was specified, -1 means it was unset, and
	// InhibitAnyPolicyZero being true mean that the field was explicitly set to
	// zero. The case of InhibitAnyPolicy==0 with InhibitAnyPolicyZero==false
	// should be treated equivalent to -1 (unset).
	InhibitAnyPolicy int
	// InhibitAnyPolicyZero indicates that InhibitAnyPolicy==0 should be
	// interpreted as an actual maximum path length of zero. Otherwise, that
	// combination is interpreted as InhibitAnyPolicy not being set.
	InhibitAnyPolicyZero bool

	// InhibitPolicyMapping and InhibitPolicyMappingZero indicate the presence
	// and value of the inhibitPolicyMapping field of the policyConstraints
	// extension.
	//
	// The value of InhibitPolicyMapping indicates the number of additional
	// certificates in the path after this certificate that may use policy
	// mapping.
	//
	// When parsing a certificate, a positive non-zero InhibitPolicyMapping
	// means that the field was specified, -1 means it was unset, and
	// InhibitPolicyMappingZero being true mean that the field was explicitly
	// set to zero. The case of InhibitPolicyMapping==0 with
	// InhibitPolicyMappingZero==false should be treated equivalent to -1
	// (unset).
	InhibitPolicyMapping int
	// InhibitPolicyMappingZero indicates that InhibitPolicyMapping==0 should be
	// interpreted as an actual maximum path length of zero. Otherwise, that
	// combination is interpreted as InhibitAnyPolicy not being set.
	InhibitPolicyMappingZero bool

	// RequireExplicitPolicy and RequireExplicitPolicyZero indicate the presence
	// and value of the requireExplicitPolicy field of the policyConstraints
	// extension.
	//
	// The value of RequireExplicitPolicy indicates the number of additional
	// certificates in the path after this certificate before an explicit policy
	// is required for the rest of the path. When an explicit policy is required,
	// each subsequent certificate in the path must contain a required policy OID,
	// or a policy OID which has been declared as equivalent through the policy
	// mapping extension.
	//
	// When parsing a certificate, a positive non-zero RequireExplicitPolicy
	// means that the field was specified, -1 means it was unset, and
	// RequireExplicitPolicyZero being true mean that the field was explicitly
	// set to zero. The case of RequireExplicitPolicy==0 with
	// RequireExplicitPolicyZero==false should be treated equivalent to -1
	// (unset).
	RequireExplicitPolicy int
	// RequireExplicitPolicyZero indicates that RequireExplicitPolicy==0 should be
	// interpreted as an actual maximum path length of zero. Otherwise, that
	// combination is interpreted as InhibitAnyPolicy not being set.
	RequireExplicitPolicyZero bool

	// PolicyMappings contains a list of policy mappings included in the certificate.
	PolicyMappings []PolicyMapping
}

// PolicyMapping represents a policy mapping entry in the policyMappings extension.
type PolicyMapping struct {
	// IssuerDomainPolicy contains a policy OID the issuing certificate considers
	// equivalent to SubjectDomainPolicy in the subject certificate.
	IssuerDomainPolicy OID
	// SubjectDomainPolicy contains a OID the issuing certificate considers
	// equivalent to IssuerDomainPolicy in the subject certificate.
	SubjectDomainPolicy OID
}

func (p *Certificate) PublicEqual(pk crypto.PublicKey) bool {
	switch k := p.PublicKey.(type) {
	case *rsa.PublicKey:
		return k.Equal(pk)
	case *ecdh.PublicKey:
		return k.Equal(pk)
	case *ecdsa.PublicKey:
		return k.Equal(pk)
	case ed25519.PublicKey:
		return k.Equal(pk)
	}
	return false
}

func (c *Certificate) Equal(other *Certificate) bool {
	if c == nil || other == nil {
		return c == other
	}
	return bytes.Equal(c.Raw, other.Raw)
}

func (c *Certificate) hasSANExtension() bool {
	return OidInExtensions(OidExtensionSubjectAltName, c.Extensions)
}

// CheckSignatureFrom verifies that the signature on c is a valid signature from parent.
//
// This is a low-level API that performs very limited checks, and not a full
// path verifier. Most users should use [Certificate.Verify] instead.
func (c *Certificate) CheckSignatureFrom(parent *Certificate) pkerr.Kerror {
	// RFC 5280, 4.2.1.9:
	// "If the basic constraints extension is not present in a version 3
	// certificate, or the extension is present but the cA boolean is not
	// asserted, then the certified public key MUST NOT be used to verify
	// certificate signatures."
	if parent.Version == 3 && !parent.BasicConstraintsValid ||
		parent.BasicConstraintsValid && !parent.IsCA {
		return pkerr.NewErrConstraintViolation()
	}

	if parent.KeyUsage != 0 && parent.KeyUsage&KeyUsageCertSign == 0 {
		return pkerr.NewErrConstraintViolation()
	}

	if parent.PublicKeyAlgorithm == pkix.UnknownPublicKeyAlgorithm {
		return pkerr.NewErrUnsupportedAlgorithm()
	}

	return c.SignatureAlgorithm.CheckSignature(c.RawTBSCertificate, c.Signature, parent.PublicKey, false)
}

// CheckSignature verifies that signature is a valid signature over signed from
// c's public key.
//
// This is a low-level API that performs no validity checks on the certificate.
//
// [RSAWithMD5] signatures are rejected, while [RSAWithSHA1] and [ECDSAWithSHA1]
// signatures are currently accepted.
func (c *Certificate) CheckSignature(algo pkix.SignatureAlgorithm, signed, signature []byte) pkerr.Kerror {
	return algo.CheckSignature(signed, signature, c.PublicKey, true)
}

func (c *Certificate) hasNameConstraints() bool {
	return OidInExtensions(oidExtensionNameConstraints, c.Extensions)
}

type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

// RFC 5280 4.2.1.4
const (
	nameTypeOther      = 0
	nameTypeEmail      = 1
	nameTypeDNS        = 2
	nameTypeDirectory  = 4
	nameTypeURI        = 6
	nameTypeIP         = 7
	nameTypeRegisterID = 8
)

// RFC 5280, 4.2.2.1
type authorityInfoAccess struct {
	Method   asn1.ObjectIdentifier
	Location asn1.RawValue
}

// RFC 5280, 4.2.1.14
type distributionPoint struct {
	DistributionPoint distributionPointName `asn1:"optional,tag:0"`
	Reason            asn1.BitString        `asn1:"optional,tag:1"`
	CRLIssuer         asn1.RawValue         `asn1:"optional,tag:2"`
}

type distributionPointName struct {
	FullName     []asn1.RawValue  `asn1:"optional,tag:0"`
	RelativeName pkix.RDNSequence `asn1:"optional,tag:1"`
}

func reverseBitsInAByte(in byte) byte {
	b1 := in>>4 | in<<4
	b2 := b1>>2&0x33 | b1<<2&0xcc
	b3 := b2>>1&0x55 | b2<<1&0xaa
	return b3
}

// asn1BitLength returns the bit-length of bitString by considering the
// most-significant bit in a byte to be the "first" bit. This convention
// matches ASN.1, but differs from almost everything else.
func asn1BitLength(bitString []byte) int {
	bitLen := len(bitString) * 8

	for i := range bitString {
		b := bitString[len(bitString)-i-1]

		for bit := uint(0); bit < 8; bit++ {
			if (b>>bit)&1 == 1 {
				return bitLen
			}
			bitLen--
		}
	}

	return 0
}

var (
	oidExtensionSubjectKeyId          = asn1.ObjectIdentifier{2, 5, 29, 14}
	OidExtensionKeyUsage              = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtensionExtendedKeyUsage      = asn1.ObjectIdentifier{2, 5, 29, 37}
	OidExtensionAuthorityKeyId        = asn1.ObjectIdentifier{2, 5, 29, 35}
	OidExtensionBasicConstraints      = asn1.ObjectIdentifier{2, 5, 29, 19}
	OidExtensionSubjectAltName        = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtensionCertificatePolicies   = asn1.ObjectIdentifier{2, 5, 29, 32}
	oidExtensionNameConstraints       = asn1.ObjectIdentifier{2, 5, 29, 30}
	oidExtensionCRLDistributionPoints = asn1.ObjectIdentifier{2, 5, 29, 31}
	oidExtensionAuthorityInfoAccess   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
)

var (
	oidAuthorityInfoAccessOcsp    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	oidAuthorityInfoAccessIssuers = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
)

// OidInExtensions reports whether an extension with the given oid exists in
// extensions.
func OidInExtensions(oid asn1.ObjectIdentifier, extensions []pkix.Extension) bool {
	for _, e := range extensions {
		if e.Id.Equal(oid) {
			return true
		}
	}
	return false
}

func marshallRegisterID(rid pkix.RegisterID) (encoded []byte, err pkerr.Kerror) {
	var data []byte
	data, err = asn1.Marshal(asn1.ObjectIdentifier(rid))
	if err != nil {
		return
	}
	return data[2:], nil
}

// MarshalSANs marshals a list of addresses into a the contents of an X.509
// SubjectAlternativeName extension.
func MarshalSANs(san *SubjectAlternativeName) (derBytes []byte, err pkerr.Kerror) {
	if san == nil {
		return
	}
	var rawValues []asn1.RawValue
	for _, name := range san.DNSNames {
		if err := asn1.IsIA5String(name); err != nil {
			return nil, err
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeDNS, Class: 2, Bytes: []byte(name)})
	}
	for _, email := range san.EmailAddresses {
		if err := asn1.IsIA5String(email); err != nil {
			return nil, err
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeEmail, Class: 2, Bytes: []byte(email)})
	}
	for _, rawIP := range san.IPAddresses {
		// If possible, we always want to encode IPv4 addresses in 4 bytes.
		ip := rawIP.To4()
		if ip == nil {
			ip = rawIP
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeIP, Class: 2, Bytes: ip})
	}
	for _, uri := range san.URIs {
		uriStr := uri.String()
		if err := asn1.IsIA5String(uriStr); err != nil {
			return nil, err
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeURI, Class: 2, Bytes: []byte(uriStr)})
	}
	for _, dirName := range san.DirectoryNames {
		var val []byte
		rdn := dirName.ToRDNSequence()
		val, err = asn1.Marshal(rdn)
		if err != nil {
			return nil, err
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeDirectory, IsCompound: true, Class: 2, Bytes: val})
	}
	for _, other := range san.OtherNames {
		var typ, val []byte
		typ, err = asn1.Marshal(other.Type)
		if err != nil {
			return nil, err
		}
		val, err = asn1.Marshal(other.Value)
		if err != nil {
			return nil, err
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeOther, IsCompound: true, Class: 2, Bytes: append(typ, val...)})
	}
	for _, oid := range san.RegisterIDs {
		var val []byte
		val, err = marshallRegisterID(oid)
		if err != nil {
			return nil, err
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeRegisterID, Class: 2, Bytes: val})
	}

	return asn1.Marshal(rawValues)
}

func buildCertExtensions(template *Certificate, subjectIsEmpty bool, authorityKeyId []byte, subjectKeyId []byte) (ret []pkix.Extension, err pkerr.Kerror) {
	ret = make([]pkix.Extension, 10 /* maximum number of elements. */)
	n := 0

	if template.KeyUsage != 0 &&
		!OidInExtensions(OidExtensionKeyUsage, template.ExtraExtensions) {
		ret[n], err = marshalKeyUsage(template.KeyUsage)
		if err != nil {
			return nil, err
		}
		n++
	}

	if (len(template.ExtKeyUsage) > 0 || len(template.UnknownExtKeyUsage) > 0) &&
		!OidInExtensions(oidExtensionExtendedKeyUsage, template.ExtraExtensions) {
		ret[n], err = marshalExtKeyUsage(template.ExtKeyUsage, template.UnknownExtKeyUsage)
		if err != nil {
			return nil, err
		}
		n++
	}

	if template.BasicConstraintsValid && !OidInExtensions(OidExtensionBasicConstraints, template.ExtraExtensions) {
		ret[n], err = marshalBasicConstraints(template.IsCA, template.MaxPathLen, template.MaxPathLenZero)
		if err != nil {
			return nil, err
		}
		n++
	}

	if len(subjectKeyId) > 0 && !OidInExtensions(oidExtensionSubjectKeyId, template.ExtraExtensions) {
		ret[n].Id = oidExtensionSubjectKeyId
		ret[n].Value, err = asn1.Marshal(subjectKeyId)
		if err != nil {
			return
		}
		n++
	}

	if len(authorityKeyId) > 0 && !OidInExtensions(OidExtensionAuthorityKeyId, template.ExtraExtensions) {
		ret[n].Id = OidExtensionAuthorityKeyId
		ret[n].Value, err = asn1.Marshal(authKeyId{authorityKeyId})
		if err != nil {
			return
		}
		n++
	}

	if (len(template.OCSPServer) > 0 || len(template.IssuingCertificateURL) > 0) &&
		!OidInExtensions(oidExtensionAuthorityInfoAccess, template.ExtraExtensions) {
		ret[n].Id = oidExtensionAuthorityInfoAccess
		var aiaValues []authorityInfoAccess
		for _, name := range template.OCSPServer {
			aiaValues = append(aiaValues, authorityInfoAccess{
				Method:   oidAuthorityInfoAccessOcsp,
				Location: asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(name)},
			})
		}
		for _, name := range template.IssuingCertificateURL {
			aiaValues = append(aiaValues, authorityInfoAccess{
				Method:   oidAuthorityInfoAccessIssuers,
				Location: asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(name)},
			})
		}
		ret[n].Value, err = asn1.Marshal(aiaValues)
		if err != nil {
			return
		}
		n++
	}

	if (template.San != nil) &&
		!OidInExtensions(OidExtensionSubjectAltName, template.ExtraExtensions) {
		ret[n].Id = OidExtensionSubjectAltName
		// From RFC 5280, Section 4.2.1.6:
		// “If the subject field contains an empty sequence ... then
		// subjectAltName extension ... is marked as critical”
		ret[n].Critical = subjectIsEmpty
		ret[n].Value, err = MarshalSANs(template.San)
		if err != nil {
			return
		}
		n++
	}

	if len(template.Policies) > 0 && !OidInExtensions(oidExtensionCertificatePolicies, template.ExtraExtensions) {
		ret[n], err = marshalCertificatePolicies(template.Policies)
		if err != nil {
			return nil, err
		}
		n++
	}

	if (len(template.PermittedDNSDomains) > 0 || len(template.ExcludedDNSDomains) > 0 ||
		len(template.PermittedIPRanges) > 0 || len(template.ExcludedIPRanges) > 0 ||
		len(template.PermittedEmailAddresses) > 0 || len(template.ExcludedEmailAddresses) > 0 ||
		len(template.PermittedURIDomains) > 0 || len(template.ExcludedURIDomains) > 0) &&
		!OidInExtensions(oidExtensionNameConstraints, template.ExtraExtensions) {
		ret[n].Id = oidExtensionNameConstraints
		ret[n].Critical = template.PermittedDNSDomainsCritical

		ipAndMask := func(ipNet *net.IPNet) []byte {
			maskedIP := ipNet.IP.Mask(ipNet.Mask)
			ipAndMask := make([]byte, 0, len(maskedIP)+len(ipNet.Mask))
			ipAndMask = append(ipAndMask, maskedIP...)
			ipAndMask = append(ipAndMask, ipNet.Mask...)
			return ipAndMask
		}

		serialiseConstraints := func(dns []string, ips []*net.IPNet, emails []string, uriDomains []string) (der []byte, err pkerr.Kerror) {
			var b pkixstring.Builder

			for _, name := range dns {
				if err = asn1.IsIA5String(name); err != nil {
					return nil, err
				}

				b.AddASN1(pkixstring.SEQUENCE, func(b *pkixstring.Builder) {
					b.AddASN1(pkixstring.Tag(2).ContextSpecific(), func(b *pkixstring.Builder) {
						b.AddBytes([]byte(name))
					})
				})
			}

			for _, ipNet := range ips {
				b.AddASN1(pkixstring.SEQUENCE, func(b *pkixstring.Builder) {
					b.AddASN1(pkixstring.Tag(7).ContextSpecific(), func(b *pkixstring.Builder) {
						b.AddBytes(ipAndMask(ipNet))
					})
				})
			}

			for _, email := range emails {
				if err = asn1.IsIA5String(email); err != nil {
					return nil, err
				}

				b.AddASN1(pkixstring.SEQUENCE, func(b *pkixstring.Builder) {
					b.AddASN1(pkixstring.Tag(1).ContextSpecific(), func(b *pkixstring.Builder) {
						b.AddBytes([]byte(email))
					})
				})
			}

			for _, uriDomain := range uriDomains {
				if err = asn1.IsIA5String(uriDomain); err != nil {
					return nil, err
				}

				b.AddASN1(pkixstring.SEQUENCE, func(b *pkixstring.Builder) {
					b.AddASN1(pkixstring.Tag(6).ContextSpecific(), func(b *pkixstring.Builder) {
						b.AddBytes([]byte(uriDomain))
					})
				})
			}

			data, nativeError := b.Bytes()
			return data, pkerr.NewErrNative(nativeError)
		}

		permitted, err := serialiseConstraints(template.PermittedDNSDomains, template.PermittedIPRanges, template.PermittedEmailAddresses, template.PermittedURIDomains)
		if err != nil {
			return nil, err
		}

		excluded, err := serialiseConstraints(template.ExcludedDNSDomains, template.ExcludedIPRanges, template.ExcludedEmailAddresses, template.ExcludedURIDomains)
		if err != nil {
			return nil, err
		}

		var b pkixstring.Builder
		b.AddASN1(pkixstring.SEQUENCE, func(b *pkixstring.Builder) {
			if len(permitted) > 0 {
				b.AddASN1(pkixstring.Tag(0).ContextSpecific().Constructed(), func(b *pkixstring.Builder) {
					b.AddBytes(permitted)
				})
			}

			if len(excluded) > 0 {
				b.AddASN1(pkixstring.Tag(1).ContextSpecific().Constructed(), func(b *pkixstring.Builder) {
					b.AddBytes(excluded)
				})
			}
		})

		var nativeError error
		ret[n].Value, nativeError = b.Bytes()
		if nativeError != nil {
			return nil, pkerr.NewErrNative(nativeError)
		}
		n++
	}

	if len(template.CRLDistributionPoints) > 0 &&
		!OidInExtensions(oidExtensionCRLDistributionPoints, template.ExtraExtensions) {
		ret[n].Id = oidExtensionCRLDistributionPoints

		var crlDp []distributionPoint
		for _, name := range template.CRLDistributionPoints {
			dp := distributionPoint{
				DistributionPoint: distributionPointName{
					FullName: []asn1.RawValue{
						{Tag: 6, Class: 2, Bytes: []byte(name)},
					},
				},
			}
			crlDp = append(crlDp, dp)
		}

		ret[n].Value, err = asn1.Marshal(crlDp)
		if err != nil {
			return
		}
		n++
	}

	// Adding another extension here? Remember to update the maximum number
	// of elements in the make() at the top of the function and the list of
	// template fields used in CreateCertificate documentation.

	return append(ret[:n], template.ExtraExtensions...), nil
}

func marshalKeyUsage(ku KeyUsage) (pkix.Extension, pkerr.Kerror) {
	ext := pkix.Extension{Id: OidExtensionKeyUsage, Critical: true}

	var a [2]byte
	a[0] = reverseBitsInAByte(byte(ku))
	a[1] = reverseBitsInAByte(byte(ku >> 8))

	l := 1
	if a[1] != 0 {
		l = 2
	}

	bitString := a[:l]
	var err pkerr.Kerror
	ext.Value, err = asn1.Marshal(asn1.BitString{Bytes: bitString, BitLength: asn1BitLength(bitString)})
	return ext, err
}

func marshalExtKeyUsage(extUsages []ExtKeyUsage, unknownUsages []asn1.ObjectIdentifier) (pkix.Extension, pkerr.Kerror) {
	ext := pkix.Extension{Id: oidExtensionExtendedKeyUsage}

	oids := make([]asn1.ObjectIdentifier, len(extUsages)+len(unknownUsages))
	for i, u := range extUsages {
		if oid, ok := oidFromExtKeyUsage(u); ok {
			oids[i] = oid
		} else {
			return ext, pkerr.NewErrUnknownEKU()
		}
	}

	copy(oids[len(extUsages):], unknownUsages)

	var err pkerr.Kerror
	ext.Value, err = asn1.Marshal(oids)
	return ext, err
}

func marshalBasicConstraints(isCA bool, maxPathLen int, maxPathLenZero bool) (pkix.Extension, pkerr.Kerror) {
	ext := pkix.Extension{Id: OidExtensionBasicConstraints, Critical: true}
	// Leaving MaxPathLen as zero indicates that no maximum path
	// length is desired, unless MaxPathLenZero is set. A value of
	// -1 causes encoding/asn1 to omit the value as desired.
	if maxPathLen == 0 && !maxPathLenZero {
		maxPathLen = -1
	}
	var err pkerr.Kerror
	ext.Value, err = asn1.Marshal(basicConstraints{isCA, maxPathLen})
	return ext, err
}

func marshalCertificatePolicies(policies []OID) (pkix.Extension, pkerr.Kerror) {
	ext := pkix.Extension{Id: oidExtensionCertificatePolicies}

	b := pkixstring.NewBuilder(make([]byte, 0, 128))
	b.AddASN1(pkixstring.SEQUENCE, func(child *pkixstring.Builder) {
		for _, v := range policies {
			child.AddASN1(pkixstring.SEQUENCE, func(child *pkixstring.Builder) {
				child.AddASN1(pkixstring.OBJECT_IDENTIFIER, func(child *pkixstring.Builder) {
					if len(v.der) == 0 {
						child.SetError(pkerr.NewErrInvalidASN1OID())
						return
					}
					child.AddBytes(v.der)
				})
			})
		}
	})

	var nativeError error
	ext.Value, nativeError = b.Bytes()
	return ext, pkerr.NewErrNative(nativeError)
}

func (cert *Certificate) SubjectBytes() ([]byte, pkerr.Kerror) {
	if len(cert.RawSubject) > 0 {
		return cert.RawSubject, nil
	}

	return asn1.Marshal(cert.Subject.ToRDNSequence())
}

// emptyASN1Subject is the ASN.1 DER encoding of an empty Subject, which is
// just an empty SEQUENCE.
var emptyASN1Subject = []byte{0x30, 0}

// CreateCertificate creates a new X.509 v3 certificate based on a template.
// The following members of template are currently used:
//
//   - AuthorityKeyId
//   - BasicConstraintsValid
//   - CRLDistributionPoints
//   - DNSNames
//   - EmailAddresses
//   - ExcludedDNSDomains
//   - ExcludedEmailAddresses
//   - ExcludedIPRanges
//   - ExcludedURIDomains
//   - ExtKeyUsage
//   - ExtraExtensions
//   - IPAddresses
//   - IsCA
//   - IssuingCertificateURL
//   - KeyUsage
//   - MaxPathLen
//   - MaxPathLenZero
//   - NotAfter
//   - NotBefore
//   - OCSPServer
//   - PermittedDNSDomains
//   - PermittedDNSDomainsCritical
//   - PermittedEmailAddresses
//   - PermittedIPRanges
//   - PermittedURIDomains
//   - PolicyIdentifiers (see note below)
//   - Policies (see note below)
//   - SerialNumber
//   - SignatureAlgorithm
//   - Subject
//   - SubjectKeyId
//   - URIs
//   - UnknownExtKeyUsage
//
// The certificate is signed by parent. If parent is equal to template then the
// certificate is self-signed. The parameter pub is the public key of the
// certificate to be generated and priv is the private key of the signer.
//
// The returned slice is the certificate in DER encoding.
//
// The currently supported key types are *rsa.PublicKey, *ecdsa.PublicKey and
// ed25519.PublicKey. pub must be a supported key type, and priv must be a
// crypto.Signer or crypto.MessageSigner with a supported public key.
//
// The AuthorityKeyId will be taken from the SubjectKeyId of parent, if any,
// unless the resulting certificate is self-signed. Otherwise the value from
// template will be used.
//
// If SubjectKeyId from template is empty and the template is a CA, SubjectKeyId
// will be generated from the hash of the public key.
//
// If template.SerialNumber is nil, a serial number will be generated which
// conforms to RFC 5280, Section 4.1.2.2 using entropy from rand.
func (parent *Certificate) SignCertificate(template *Certificate, pub, priv any) ([]byte, pkerr.Kerror) {
	key, ok := priv.(crypto.Signer)
	if !ok {
		return nil, pkerr.NewErrPrivateKeyNotASigner()
	}

	serialNumber := template.SerialNumber
	if serialNumber == nil {
		// Generate a serial number following RFC 5280, Section 4.1.2.2 if one
		// is not provided. The serial number must be positive and at most 20
		// octets *when encoded*.
		serialBytes := make([]byte, 20)
		if _, nativeError := io.ReadFull(rand.Reader, serialBytes); nativeError != nil {
			return nil, pkerr.NewErrNative(nativeError)
		}
		// If the top bit is set, the serial will be padded with a leading zero
		// byte during encoding, so that it's not interpreted as a negative
		// integer. This padding would make the serial 21 octets so we clear the
		// top bit to ensure the correct length in all cases.
		serialBytes[0] &= 0b0111_1111
		serialNumber = new(big.Int).SetBytes(serialBytes)
	}

	// RFC 5280 Section 4.1.2.2: serial number must be positive
	//
	// We _should_ also restrict serials to <= 20 octets, but it turns out a lot of people
	// get this wrong, in part because the encoding can itself alter the length of the
	// serial. For now we accept these non-conformant serials.
	if serialNumber.Sign() == -1 {
		return nil, pkerr.NewErrSerialNumberNegative()
	}

	if template.BasicConstraintsValid && template.MaxPathLen < -1 {
		return nil, pkerr.NewErrMaxPathLenNegative()
	}

	if template.BasicConstraintsValid && !template.IsCA && template.MaxPathLen != -1 && (template.MaxPathLen != 0 || template.MaxPathLenZero) {
		return nil, pkerr.NewErrMaxPathLenOnlyCA()
	}

	signatureAlgorithm, algorithmIdentifier, err := template.SignatureAlgorithm.SigningParamsForKey(key)
	if err != nil {
		return nil, err
	}

	publicKeyBytes, publicKeyAlgorithm, err := keys.MarshalPublicKey(pub)
	if err != nil {
		return nil, err
	}
	if pkix.GetPublicKeyAlgorithmFromOID(publicKeyAlgorithm.Algorithm) == pkix.UnknownPublicKeyAlgorithm {
		return nil, pkerr.NewErrUnsupportedPublicKeyType(pub)
	}

	asn1Issuer, err := parent.SubjectBytes()
	if err != nil {
		return nil, err
	}

	asn1Subject, err := template.SubjectBytes()
	if err != nil {
		return nil, err
	}

	authorityKeyId := template.AuthorityKeyId
	if !bytes.Equal(asn1Issuer, asn1Subject) && len(parent.SubjectKeyId) > 0 {
		authorityKeyId = parent.SubjectKeyId
	}

	subjectKeyId := template.SubjectKeyId
	if len(subjectKeyId) == 0 && template.IsCA {
		// SubjectKeyId generated using method 1 in RFC 7093, Section 2:
		//    1) The keyIdentifier is composed of the leftmost 160-bits of the
		//    SHA-256 hash of the value of the BIT STRING subjectPublicKey
		//    (excluding the tag, length, and number of unused bits).
		h := sha256.Sum256(publicKeyBytes)
		subjectKeyId = h[:20]
	}

	// Check that the signer's public key matches the private key, if available.
	type privateKey interface {
		Equal(crypto.PublicKey) bool
	}
	if privPub, ok := key.Public().(privateKey); !ok {
		return nil, pkerr.NewErrPublicKeyTypeNoEqual()
	} else if parent.PublicKey != nil && !privPub.Equal(parent.PublicKey) {
		return nil, pkerr.NewErrPrivateKeyDoesNotMatchParentPublicKey()
	}

	extensions, err := buildCertExtensions(template, bytes.Equal(asn1Subject, emptyASN1Subject), authorityKeyId, subjectKeyId)
	if err != nil {
		return nil, err
	}

	encodedPublicKey := asn1.BitString{BitLength: len(publicKeyBytes) * 8, Bytes: publicKeyBytes}
	c := tbsCertificate{
		Version:            2,
		SerialNumber:       serialNumber,
		SignatureAlgorithm: algorithmIdentifier,
		Issuer:             asn1.RawValue{FullBytes: asn1Issuer},
		Validity:           validity{template.NotBefore.UTC(), template.NotAfter.UTC()},
		Subject:            asn1.RawValue{FullBytes: asn1Subject},
		PublicKey:          keys.PublicKeyInfo{ /*Raw: nil, */ Algorithm: publicKeyAlgorithm, PublicKey: encodedPublicKey},
		Extensions:         extensions,
	}

	tbsCertContents, err := asn1.Marshal(c)
	if err != nil {
		return nil, err
	}
	c.Raw = tbsCertContents

	signature, err := signatureAlgorithm.Sign(tbsCertContents, key)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(certificate{
		TBSCertificate:     c,
		SignatureAlgorithm: algorithmIdentifier,
		SignatureValue:     asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
}

func (cert *Certificate) MarshelAki() ([]byte, pkerr.Kerror) {
	return asn1.Marshal(authKeyId{Id: cert.SubjectKeyId})
}
