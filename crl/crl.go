package crl

import (
	"bytes"
	"crypto"
	"math/big"
	"time"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/internal/pkixstring"
	"github.com/pduveau/gocert/pkerr"
	"github.com/pduveau/gocert/pkix"
	"github.com/pduveau/gocert/x509"
)

var (
	oidExtensionCRLNumber  = asn1.ObjectIdentifier{2, 5, 29, 20}
	oidExtensionReasonCode = asn1.ObjectIdentifier{2, 5, 29, 21}
)

// RevokedCertificate represents the ASN.1 structure of the same name. See RFC
// 5280, section 5.1.
type RevokedCertificate struct {
	SerialNumber   *big.Int
	RevocationTime time.Time
	Extensions     []pkix.Extension `asn1:"optional"`
}

// RevocationListEntry represents an entry in the revokedCertificates
// sequence of a CRL.
type RevocationListEntry struct {
	// Raw contains the raw bytes of the revokedCertificates entry. It is set when
	// parsing a CRL; it is ignored when generating a CRL.
	Raw []byte

	// SerialNumber represents the serial number of a revoked certificate. It is
	// both used when creating a CRL and populated when parsing a CRL. It must not
	// be nil.
	SerialNumber *big.Int
	// RevocationTime represents the time at which the certificate was revoked. It
	// is both used when creating a CRL and populated when parsing a CRL. It must
	// not be the zero time.
	RevocationTime time.Time
	// ReasonCode represents the reason for revocation, using the integer enum
	// values specified in RFC 5280 Section 5.3.1. When creating a CRL, the zero
	// value will result in the reasonCode extension being omitted. When parsing a
	// CRL, the zero value may represent either the reasonCode extension being
	// absent (which implies the default revocation reason of 0/Unspecified), or
	// it may represent the reasonCode extension being present and explicitly
	// containing a value of 0/Unspecified (which should not happen according to
	// the DER encoding rules, but can and does happen anyway).
	ReasonCode int

	// Extensions contains raw X.509 extensions. When parsing CRL entries,
	// this can be used to extract non-critical extensions that are not
	// parsed by this package. When marshaling CRL entries, the Extensions
	// field is ignored, see ExtraExtensions.
	Extensions []pkix.Extension
	// ExtraExtensions contains extensions to be copied, raw, into any
	// marshaled CRL entries. Values override any extensions that would
	// otherwise be produced based on the other fields. The ExtraExtensions
	// field is not populated when parsing CRL entries, see Extensions.
	ExtraExtensions []pkix.Extension
}

// RevocationList represents a [Certificate] Revocation List (CRL) as specified
// by RFC 5280.
type RevocationList struct {
	// Raw contains the complete ASN.1 DER content of the CRL (tbsCertList,
	// signatureAlgorithm, and signatureValue.)
	Raw []byte
	// RawTBSRevocationList contains just the tbsCertList portion of the ASN.1
	// DER.
	RawTBSRevocationList []byte
	// RawIssuer contains the DER encoded Issuer.
	RawIssuer []byte

	// Issuer contains the DN of the issuing certificate.
	Issuer pkix.Name
	// AuthorityKeyId is used to identify the public key associated with the
	// issuing certificate. It is populated from the authorityKeyIdentifier
	// extension when parsing a CRL. It is ignored when creating a CRL; the
	// extension is populated from the issuing certificate itself.
	AuthorityKeyId []byte

	Signature []byte
	// SignatureAlgorithm is used to determine the signature algorithm to be
	// used when signing the CRL. If 0 the default algorithm for the signing
	// key will be used.
	SignatureAlgorithm pkix.SignatureAlgorithm

	// RevokedCertificateEntries represents the revokedCertificates sequence in
	// the CRL. It is used when creating a CRL and also populated when parsing a
	// CRL. When creating a CRL, it may be empty or nil, in which case the
	// revokedCertificates ASN.1 sequence will be omitted from the CRL entirely.
	RevokedCertificateEntries []RevocationListEntry

	// Number is used to populate the X.509 v2 cRLNumber extension in the CRL,
	// which should be a monotonically increasing sequence number for a given
	// CRL scope and CRL issuer. It is also populated from the cRLNumber
	// extension when parsing a CRL.
	Number *big.Int

	// ThisUpdate is used to populate the thisUpdate field in the CRL, which
	// indicates the issuance date of the CRL.
	ThisUpdate time.Time
	// NextUpdate is used to populate the nextUpdate field in the CRL, which
	// indicates the date by which the next CRL will be issued. NextUpdate
	// must be greater than ThisUpdate.
	NextUpdate time.Time

	// Extensions contains raw X.509 extensions. When creating a CRL,
	// the Extensions field is ignored, see ExtraExtensions.
	Extensions []pkix.Extension

	// ExtraExtensions contains any additional extensions to add directly to
	// the CRL.
	ExtraExtensions []pkix.Extension
}

// These structures reflect the ASN.1 structure of X.509 CRLs better than
// the existing crypto/x509/pkix variants do. These mirror the existing
// certificate structs in this file.
//
// Notably, we include issuer as an asn1.RawValue, mirroring the behavior of
// tbsCertificate and allowing raw (unparsed) subjects to be passed cleanly.
type CertificateList struct {
	TBSCertList        tbsCertificateList
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type tbsCertificateList struct {
	Raw                 asn1.RawContent
	Version             int `asn1:"optional,default:0"`
	Signature           pkix.AlgorithmIdentifier
	Issuer              asn1.RawValue
	ThisUpdate          time.Time
	NextUpdate          time.Time            `asn1:"optional"`
	RevokedCertificates []RevokedCertificate `asn1:"optional"`
	Extensions          []pkix.Extension     `asn1:"tag:0,optional,explicit"`
}

// CreateRevocationList creates a new X.509 v2 [Certificate] Revocation List,
// according to RFC 5280, based on template.
//
// The CRL is signed by priv which should be a crypto.Signer or
// crypto.MessageSigner associated with the public key in the issuer
// certificate.
//
// The issuer may not be nil, and the crlSign bit must be set in [KeyUsage] in
// order to use it as a CRL issuer.
//
// The issuer distinguished name CRL field and authority key identifier
// extension are populated using the issuer certificate. issuer must have
// SubjectKeyId set.
func CreateRevocationList(template *RevocationList, issuer *x509.Certificate, priv crypto.Signer) ([]byte, pkerr.Kerror) {
	if template == nil {
		return nil, pkerr.NewErrNilTemplate()
	}
	if issuer == nil {
		return nil, pkerr.NewErrNilIssuer()
	}
	if (issuer.KeyUsage & x509.KeyUsageCRLSign) == 0 {
		return nil, pkerr.NewErrIssuerWithoutCrlSign()
	}
	if len(issuer.SubjectKeyId) == 0 {
		return nil, pkerr.NewErrIssuerWithoutSKI()
	}
	if template.NextUpdate.Before(template.ThisUpdate) {
		return nil, pkerr.NewErrThisAndNextUpdateOrder()
	}
	if template.Number == nil {
		return nil, pkerr.NewErrNumberNil()
	}

	signatureAlgorithm, algorithmIdentifier, err := template.SignatureAlgorithm.SigningParamsForKey(priv)
	if err != nil {
		return nil, err
	}

	var revokedCerts []RevokedCertificate
	// Convert the ReasonCode field to a proper extension, and force revocation times to UTC per RFC 5280.
	revokedCerts = make([]RevokedCertificate, len(template.RevokedCertificateEntries))
	for i, rce := range template.RevokedCertificateEntries {
		if rce.SerialNumber == nil {
			return nil, pkerr.NewErrNilSerialEntries()
		}
		if rce.RevocationTime.IsZero() {
			return nil, pkerr.NewErrNoRevocationTimeEntries()
		}

		rc := RevokedCertificate{
			SerialNumber:   rce.SerialNumber,
			RevocationTime: rce.RevocationTime.UTC(),
		}

		// Copy over any extra extensions, except for a Reason Code extension,
		// because we'll synthesize that ourselves to ensure it is correct.
		exts := make([]pkix.Extension, 0, len(rce.ExtraExtensions))
		for _, ext := range rce.ExtraExtensions {
			if ext.Id.Equal(oidExtensionReasonCode) {
				return nil, pkerr.NewErrReasonCodeExtraExtensionEntries()
			}
			exts = append(exts, ext)
		}

		// Only add a reasonCode extension if the reason is non-zero, as per
		// RFC 5280 Section 5.3.1.
		if rce.ReasonCode != 0 {
			reasonBytes, err := asn1.Marshal(asn1.Enumerated(rce.ReasonCode))
			if err != nil {
				return nil, err
			}

			exts = append(exts, pkix.Extension{
				Id:    oidExtensionReasonCode,
				Value: reasonBytes,
			})
		}

		if len(exts) > 0 {
			rc.Extensions = exts
		}
		revokedCerts[i] = rc
	}

	aki, err := issuer.MarshelAki()
	if err != nil {
		return nil, err
	}

	if numBytes := template.Number.Bytes(); len(numBytes) > 20 || (len(numBytes) == 20 && numBytes[0]&0x80 != 0) {
		return nil, pkerr.NewErrCRLNumberExceedMaxLength()
	}
	crlNum, err := asn1.Marshal(template.Number)
	if err != nil {
		return nil, err
	}

	// Correctly use the issuer's subject sequence if one is specified.
	issuerSubject, err := issuer.SubjectBytes()
	if err != nil {
		return nil, err
	}

	tbsCertList := tbsCertificateList{
		Version:    1, // v2
		Signature:  algorithmIdentifier,
		Issuer:     asn1.RawValue{FullBytes: issuerSubject},
		ThisUpdate: template.ThisUpdate.UTC(),
		NextUpdate: template.NextUpdate.UTC(),
		Extensions: []pkix.Extension{
			{
				Id:    x509.OidExtensionAuthorityKeyId,
				Value: aki,
			},
			{
				Id:    oidExtensionCRLNumber,
				Value: crlNum,
			},
		},
	}
	if len(revokedCerts) > 0 {
		tbsCertList.RevokedCertificates = revokedCerts
	}

	if len(template.ExtraExtensions) > 0 {
		tbsCertList.Extensions = append(tbsCertList.Extensions, template.ExtraExtensions...)
	}

	tbsCertListContents, err := asn1.Marshal(tbsCertList)
	if err != nil {
		return nil, err
	}

	// Optimization to only marshal this struct once, when signing and
	// then embedding in certificateList below.
	tbsCertList.Raw = tbsCertListContents

	signature, err := signatureAlgorithm.Sign(tbsCertListContents, priv)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(CertificateList{
		TBSCertList:        tbsCertList,
		SignatureAlgorithm: algorithmIdentifier,
		SignatureValue:     asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
}

// CheckSignatureFrom verifies that the signature on rl is a valid signature
// from issuer.
func (rl *RevocationList) CheckSignatureFrom(parent *x509.Certificate) pkerr.Kerror {
	if parent.Version == 3 && !parent.BasicConstraintsValid ||
		parent.BasicConstraintsValid && !parent.IsCA {
		return pkerr.NewErrConstraintViolation()
	}

	if parent.KeyUsage != 0 && parent.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return pkerr.NewErrConstraintViolation()
	}

	if parent.PublicKeyAlgorithm == pkix.UnknownPublicKeyAlgorithm {
		return pkerr.NewErrUnsupportedAlgorithm()
	}

	return parent.CheckSignature(rl.SignatureAlgorithm, rl.RawTBSRevocationList, rl.Signature)
}

// The X.509 standards confusingly 1-indexed the version names, but 0-indexed
// the actual encoded version, so the version for X.509v2 is 1.
const x509v2Version = 1

// ParseRevocationList parses a X509 v2 [Certificate] Revocation List from the given
// ASN.1 DER data.
func ParseRevocationList(der []byte) (*RevocationList, pkerr.Kerror) {
	rl := &RevocationList{}

	input := pkixstring.String(der)
	// we read the SEQUENCE including length and tag bytes so that
	// we can populate RevocationList.Raw, before unwrapping the
	// SEQUENCE so it can be operated on
	if !input.ReadASN1Element(&input, pkixstring.SEQUENCE) {
		return nil, pkerr.NewErrMalformedCrl()
	}
	rl.Raw = input
	if !input.ReadASN1(&input, pkixstring.SEQUENCE) {
		return nil, pkerr.NewErrMalformedCrl()
	}

	var tbs pkixstring.String
	// do the same trick again as above to extract the raw
	// bytes for Certificate.RawTBSCertificate
	if !input.ReadASN1Element(&tbs, pkixstring.SEQUENCE) {
		return nil, pkerr.NewErrMalformedTbsCrl()
	}
	rl.RawTBSRevocationList = tbs
	if !tbs.ReadASN1(&tbs, pkixstring.SEQUENCE) {
		return nil, pkerr.NewErrMalformedTbsCrl()
	}

	var version int
	if !tbs.PeekASN1Tag(pkixstring.INTEGER) {
		return nil, pkerr.NewErrUnsupportedCrlVersion(x509v2Version)
	}
	if !tbs.ReadASN1Integer(&version) {
		return nil, pkerr.NewErrMalformedCrl()
	}
	if version != x509v2Version {
		return nil, pkerr.NewErrUnsupportedCrlVersion(version)
	}

	var sigAISeq pkixstring.String
	if !tbs.ReadASN1(&sigAISeq, pkixstring.SEQUENCE) {
		return nil, pkerr.NewErrInvalidAlgorithmIdentifier()
	}
	// Before parsing the inner algorithm identifier, extract
	// the outer algorithm identifier and make sure that they
	// match.
	var outerSigAISeq pkixstring.String
	if !input.ReadASN1(&outerSigAISeq, pkixstring.SEQUENCE) {
		return nil, pkerr.NewErrInvalidAlgorithmIdentifier()
	}
	if !bytes.Equal(outerSigAISeq, sigAISeq) {
		return nil, pkerr.NewErrInconsistentAlgorithms()
	}
	sigAI, err := sigAISeq.ParseAI()
	if err != nil {
		return nil, err
	}
	rl.SignatureAlgorithm = sigAI.GetSignatureAlgorithm()

	var signature asn1.BitString
	if !input.ReadASN1BitString(&signature) {
		return nil, pkerr.NewErrInvalidSignature("")
	}
	rl.Signature = signature.RightAlign()

	var issuerSeq pkixstring.String
	if !tbs.ReadASN1Element(&issuerSeq, pkixstring.SEQUENCE) {
		return nil, pkerr.NewErrInvalidIssuer()
	}
	rl.RawIssuer = issuerSeq
	issuerRDNs, err := issuerSeq.ParseName()
	if err != nil {
		return nil, err
	}
	rl.Issuer.FillFromRDNSequence(issuerRDNs)

	rl.ThisUpdate, err = tbs.ParseTime()
	if err != nil {
		return nil, err
	}
	if tbs.PeekASN1Tag(pkixstring.GeneralizedTime) || tbs.PeekASN1Tag(pkixstring.UTCTime) {
		rl.NextUpdate, err = tbs.ParseTime()
		if err != nil {
			return nil, err
		}
	}

	if tbs.PeekASN1Tag(pkixstring.SEQUENCE) {
		var revokedSeq pkixstring.String
		if !tbs.ReadASN1(&revokedSeq, pkixstring.SEQUENCE) {
			return nil, pkerr.NewErrMalformedCrl()
		}
		for !revokedSeq.Empty() {
			rce := RevocationListEntry{}

			var certSeq pkixstring.String
			if !revokedSeq.ReadASN1Element(&certSeq, pkixstring.SEQUENCE) {
				return nil, pkerr.NewErrMalformedCrl()
			}
			rce.Raw = certSeq
			if !certSeq.ReadASN1(&certSeq, pkixstring.SEQUENCE) {
				return nil, pkerr.NewErrMalformedCrl()
			}

			rce.SerialNumber = new(big.Int)
			if !certSeq.ReadASN1Integer(rce.SerialNumber) {
				return nil, pkerr.NewErrMalformedSerialNumber()
			}
			rce.RevocationTime, err = certSeq.ParseTime()
			if err != nil {
				return nil, err
			}
			var extensions pkixstring.String
			var present bool
			if !certSeq.ReadOptionalASN1(&extensions, &present, pkixstring.SEQUENCE) {
				return nil, pkerr.NewErrMalformedExtensions()
			}
			if present {
				for !extensions.Empty() {
					var extension pkixstring.String
					if !extensions.ReadASN1(&extension, pkixstring.SEQUENCE) {
						return nil, pkerr.NewErrMalformedExtensions()
					}
					ext, err := extension.ParseExtension()
					if err != nil {
						return nil, err
					}
					if ext.Id.Equal(oidExtensionReasonCode) {
						val := pkixstring.String(ext.Value)
						if !val.ReadASN1Enum(&rce.ReasonCode) {
							return nil, pkerr.NewErrMalformedExtensions()
						}
					}
					rce.Extensions = append(rce.Extensions, ext)
				}
			}

			rl.RevokedCertificateEntries = append(rl.RevokedCertificateEntries, rce)
		}
	}

	var extensions pkixstring.String
	var present bool
	if !tbs.ReadOptionalASN1(&extensions, &present, pkixstring.Tag(0).Constructed().ContextSpecific()) {
		return nil, pkerr.NewErrMalformedExtensions()
	}
	if present {
		if !extensions.ReadASN1(&extensions, pkixstring.SEQUENCE) {
			return nil, pkerr.NewErrMalformedExtensions()
		}
		for !extensions.Empty() {
			var extension pkixstring.String
			if !extensions.ReadASN1(&extension, pkixstring.SEQUENCE) {
				return nil, pkerr.NewErrMalformedExtensions()
			}
			ext, err := extension.ParseExtension()
			if err != nil {
				return nil, err
			}
			if ext.Id.Equal(x509.OidExtensionAuthorityKeyId) {
				rl.AuthorityKeyId, err = pkixstring.ParseAuthorityKeyIdentifier(ext)
				if err != nil {
					return nil, err
				}
			} else if ext.Id.Equal(oidExtensionCRLNumber) {
				value := pkixstring.String(ext.Value)
				rl.Number = new(big.Int)
				if !value.ReadASN1Integer(rl.Number) {
					return nil, pkerr.NewErrMalformedCrlNumber()
				}
			}
			rl.Extensions = append(rl.Extensions, ext)
		}
	}

	return rl, nil
}
