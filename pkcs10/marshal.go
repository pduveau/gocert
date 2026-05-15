package pkcs10

import (
	"crypto"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/keys"
	"github.com/pduveau/gocert/pkerr"
	"github.com/pduveau/gocert/pkix"
	"github.com/pduveau/gocert/x509"
)

// CertificateRequest represents a PKCS #10, certificate signature request.
type CertificateRequest struct {
	Raw                      []byte // Complete ASN.1 DER content (CSR, signature algorithm and signature).
	RawTBSCertificateRequest []byte // Certificate request info part of raw ASN.1 DER content.
	//	RawSubjectPublicKeyInfo  []byte // DER encoded SubjectPublicKeyInfo.
	RawSubject []byte // DER encoded Subject.

	Version            int
	Signature          []byte
	SignatureAlgorithm pkix.SignatureAlgorithm

	PublicKeyAlgorithm pkix.PublicKeyAlgorithm
	PublicKey          any

	Subject pkix.Name

	// Extensions contains all requested extensions, in raw form. When parsing
	// CSRs, this can be used to extract extensions that are not parsed by this
	// package.
	Extensions []pkix.Extension

	// ExtraExtensions contains extensions to be copied, raw, into any CSR
	// marshaled by CreateCertificateRequest. Values override any extensions
	// that would otherwise be produced based on the other fields but are
	// overridden by any extensions specified in Attributes.
	//
	// The ExtraExtensions field is not populated by ParseCertificateRequest,
	// see Extensions instead.
	ExtraExtensions []pkix.Extension

	// Subject Alternate Name values.
	San *x509.SubjectAlternativeName
}

// These structures reflect the ASN.1 structure of X.509 certificate
// signature requests (see RFC 2986):

type tbsCertificateRequest struct {
	Raw           asn1.RawContent
	Version       int
	Subject       asn1.RawValue
	PublicKey     keys.PublicKeyInfo
	RawAttributes []asn1.RawValue `asn1:"tag:0"`
}

type certificateRequest struct {
	Raw                asn1.RawContent
	TBSCSR             tbsCertificateRequest
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// oidExtensionRequest is a PKCS #9 OBJECT IDENTIFIER that indicates requested
// extensions in a CSR.
var oidExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}

func (template *CertificateRequest) buildCSRExtensions() ([]pkix.Extension, pkerr.Kerror) {
	var ret []pkix.Extension

	if (template.San != nil) &&
		!x509.OidInExtensions(x509.OidExtensionSubjectAltName, template.ExtraExtensions) {
		sanBytes, err := x509.MarshalSANs(template.San)
		if err != nil {
			return nil, err
		}

		ret = append(ret, pkix.Extension{
			Id:    x509.OidExtensionSubjectAltName,
			Value: sanBytes,
		})
	}

	return append(ret, template.ExtraExtensions...), nil
}

// parseCSRExtensions parses the attributes from a CSR and extracts any
// requested extensions.
func parseCSRExtensions(rawAttributes []asn1.RawValue) ([]pkix.Extension, pkerr.Kerror) {
	// pkcs10Attribute reflects the Attribute structure from RFC 2986, Section 4.1.
	type pkcs10Attribute struct {
		Id     asn1.ObjectIdentifier
		Values []asn1.RawValue `asn1:"set"`
	}

	var ret []pkix.Extension
	requestedExts := make(map[string]bool)
	for _, rawAttr := range rawAttributes {
		var attr pkcs10Attribute
		if rest, err := asn1.Unmarshal(rawAttr.FullBytes, &attr); err != nil || len(rest) != 0 || len(attr.Values) == 0 {
			// Ignore attributes that don't parse.
			continue
		}

		if !attr.Id.Equal(oidExtensionRequest) {
			continue
		}

		var extensions []pkix.Extension
		if _, err := asn1.Unmarshal(attr.Values[0].FullBytes, &extensions); err != nil {
			return nil, err
		}
		for _, ext := range extensions {
			oidStr := ext.Id.String()
			if requestedExts[oidStr] {
				return nil, pkerr.NewErrDuplicateExtensionInCertificateRequest()
			}
			requestedExts[oidStr] = true
		}
		ret = append(ret, extensions...)
	}

	return ret, nil
}

// CreateCertificateRequest creates a new certificate request based on a
// template. The following members of template are used:
//
//   - SignatureAlgorithm
//   - Subject
//   - DNSNames
//   - EmailAddresses
//   - IPAddresses
//   - URIs
//   - ExtraExtensions
//
// priv is the private key to sign the CSR with, and the corresponding public
// key will be included in the CSR. It must implement crypto.Signer or
// crypto.MessageSigner and its Public() method must return a *rsa.PublicKey or
// a *ecdsa.PublicKey or a ed25519.PublicKey. (A *rsa.PrivateKey,
// *ecdsa.PrivateKey or ed25519.PrivateKey satisfies this.)
//
// The returned slice is the certificate request in DER encoding.
func (template *CertificateRequest) CreateCertificateRequest(priv any) (csr []byte, err pkerr.Kerror) {
	key, ok := priv.(crypto.Signer)
	if !ok {
		return nil, pkerr.NewErrPrivateKeyIsNotSigner()
	}

	signatureAlgorithm, algorithmIdentifier, err := template.SignatureAlgorithm.SigningParamsForKey(key)
	if err != nil {
		return nil, err
	}

	var publicKeyBytes []byte
	var publicKeyAlgorithm pkix.AlgorithmIdentifier
	publicKeyBytes, publicKeyAlgorithm, err = keys.MarshalPublicKey(key.Public())
	if err != nil {
		return nil, err
	}

	extensions, err := template.buildCSRExtensions()
	if err != nil {
		return nil, err
	}

	var rawAttributes = []asn1.RawValue{}

	// If not included in attributes, add a new attribute for the
	// extensions.
	if len(extensions) > 0 {
		attr := struct {
			Type  asn1.ObjectIdentifier
			Value [][]pkix.Extension `asn1:"set"`
		}{
			Type:  oidExtensionRequest,
			Value: [][]pkix.Extension{extensions},
		}

		b, err := asn1.Marshal(attr)
		if err != nil {
			return nil, pkerr.NewErrFailtoMarshalExtensions(err)
		}

		var rawValue asn1.RawValue
		if _, err := asn1.Unmarshal(b, &rawValue); err != nil {
			return nil, err
		}

		rawAttributes = append(rawAttributes, rawValue)
	}

	asn1Subject := template.RawSubject
	if len(asn1Subject) == 0 {
		asn1Subject, err = asn1.Marshal(template.Subject.ToRDNSequence())
		if err != nil {
			return nil, err
		}
	}

	tbsCSR := tbsCertificateRequest{
		Version: 0, // PKCS #10, RFC 2986
		Subject: asn1.RawValue{FullBytes: asn1Subject},
		PublicKey: keys.PublicKeyInfo{
			Algorithm: publicKeyAlgorithm,
			PublicKey: asn1.BitString{
				Bytes:     publicKeyBytes,
				BitLength: len(publicKeyBytes) * 8,
			},
		},
		RawAttributes: rawAttributes,
	}

	tbsCSRContents, err := asn1.Marshal(tbsCSR)
	if err != nil {
		return nil, err
	}
	tbsCSR.Raw = tbsCSRContents

	signature, err := signatureAlgorithm.Sign(tbsCSRContents, key)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(certificateRequest{
		TBSCSR:             tbsCSR,
		SignatureAlgorithm: algorithmIdentifier,
		SignatureValue:     asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
}

// ParseCertificateRequest parses a single certificate request from the
// given ASN.1 DER data.
func ParseCertificateRequest(asn1Data []byte) (*CertificateRequest, pkerr.Kerror) {
	var csr certificateRequest

	rest, err := asn1.Unmarshal(asn1Data, &csr)
	if err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, pkerr.NewErrASN1TrailingData("certificate request")
	}

	return parseCertificateRequest(&csr)
}

func parseCertificateRequest(in *certificateRequest) (*CertificateRequest, pkerr.Kerror) {
	out := &CertificateRequest{
		Raw:                      in.Raw,
		RawTBSCertificateRequest: in.TBSCSR.Raw,
		//		RawSubjectPublicKeyInfo:  in.TBSCSR.PublicKey.Raw,
		RawSubject: in.TBSCSR.Subject.FullBytes,

		Signature:          in.SignatureValue.RightAlign(),
		SignatureAlgorithm: in.SignatureAlgorithm.GetSignatureAlgorithm(),

		PublicKeyAlgorithm: pkix.GetPublicKeyAlgorithmFromOID(in.TBSCSR.PublicKey.Algorithm.Algorithm),

		Version: in.TBSCSR.Version,
	}

	var err pkerr.Kerror
	if out.PublicKeyAlgorithm != pkix.UnknownPublicKeyAlgorithm {
		out.PublicKey, err = in.TBSCSR.PublicKey.ParsePublicKey()
		if err != nil {
			return nil, err
		}
	}

	var subject pkix.RDNSequence
	if rest, err := asn1.Unmarshal(in.TBSCSR.Subject.FullBytes, &subject); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, pkerr.NewErrASN1TrailingData("X.509 Subject")
	}

	out.Subject.FillFromRDNSequence(&subject)

	if out.Extensions, err = parseCSRExtensions(in.TBSCSR.RawAttributes); err != nil {
		return nil, err
	}

	for _, extension := range out.Extensions {
		switch {
		case extension.Id.Equal(x509.OidExtensionSubjectAltName):
			out.San, err = x509.ParseSANExtension(extension.Value)
			if err != nil {
				return nil, err
			}
		}
	}

	return out, nil
}

// CheckSignature reports whether the signature on c is valid.
func (c *CertificateRequest) CheckSignature() pkerr.Kerror {
	return c.SignatureAlgorithm.CheckSignature(c.RawTBSCertificateRequest, c.Signature, c.PublicKey, true)
}
