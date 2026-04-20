package pkcs7

import (
	"crypto/subtle"
	"time"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/pkerr"
	"github.com/pduveau/gocert/pkix"
	"github.com/pduveau/gocert/x509"
)

// Verify is a wrapper around VerifyWithChain() that initializes an empty
// trust store, effectively disabling certificate verification when validating
// a signature.
func (p7 *PKCS7) Verify() (err pkerr.Kerror) {
	return p7.VerifyWithChain(nil)
}

// VerifyWithChain checks the signatures of a PKCS7 object.
//
// If truststore is not nil, it also verifies the chain of trust of
// the end-entity signer cert to one of the roots in the
// truststore. When the PKCS7 object includes the signing time
// authenticated attr verifies the chain at that time and UTC now
// otherwise.
func (p7 *PKCS7) VerifyWithChain(truststore *x509.CertPool) (err pkerr.Kerror) {
	if len(p7.Signers) == 0 {
		return pkerr.NewErrMsgWithoutSigners()
	}
	for _, signer := range p7.Signers {
		if err := verifySignature(p7, signer, truststore); err != nil {
			return err
		}
	}
	return nil
}

// VerifyWithChainAtTime checks the signatures of a PKCS7 object.
//
// If truststore is not nil, it also verifies the chain of trust of
// the end-entity signer cert to a root in the truststore at
// currentTime. It does not use the signing time authenticated
// attribute.
func (p7 *PKCS7) VerifyWithChainAtTime(truststore *x509.CertPool, currentTime time.Time) (err pkerr.Kerror) {
	if len(p7.Signers) == 0 {
		return pkerr.NewErrMsgWithoutSigners()
	}
	for _, signer := range p7.Signers {
		signedData := p7.Content
		ee := getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
		if ee == nil {
			return pkerr.NewErrNoCertificateForSigner()
		}
		if len(signer.AuthenticatedAttributes) > 0 {
			// TODO(fullsailor): First check the content type match
			var (
				digest      []byte
				signingTime time.Time
			)
			err := unmarshalAttribute(signer.AuthenticatedAttributes, OIDAttributeMessageDigest, &digest)
			if err != nil {
				return err
			}
			hash, err := pkix.GetHashForOID(signer.DigestAlgorithm.Algorithm)
			if err != nil {
				return err
			}
			h := hash.New()
			h.Write(p7.Content)
			computed := h.Sum(nil)
			if subtle.ConstantTimeCompare(digest, computed) != 1 {
				return pkerr.NewErrMessageDigestMismatch()
			}
			signedData, err = marshalAttributes(signer.AuthenticatedAttributes)
			if err != nil {
				return err
			}
			err = unmarshalAttribute(signer.AuthenticatedAttributes, OIDAttributeSigningTime, &signingTime)
			if err == nil {
				// signing time found, performing validity check
				if signingTime.After(ee.NotAfter) || signingTime.Before(ee.NotBefore) {
					return pkerr.NewErrSigningTimeOutOfValidity(
						signingTime.Format(time.RFC3339),
						ee.NotBefore.Format(time.RFC3339),
						ee.NotAfter.Format(time.RFC3339))
				}
			}
		}
		if truststore != nil {
			_, err = verifyCertChain(ee, p7.Certificates, truststore, currentTime)
			if err != nil {
				return err
			}
		}
		sigalg, err := pkix.GetSignatureAlgorithm(signer.DigestEncryptionAlgorithm, signer.DigestAlgorithm)
		if err != nil {
			return err
		}
		err = ee.CheckSignature(sigalg, signedData, signer.EncryptedDigest)
		if err != nil {
			return err
		}
	}
	return nil
}

func verifySignature(p7 *PKCS7, signer signerInfo, truststore *x509.CertPool) (err pkerr.Kerror) {
	signedData := p7.Content
	ee := getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
	if ee == nil {
		return pkerr.NewErrNoCertificateForSigner()
	}
	signingTime := time.Now().UTC()
	if len(signer.AuthenticatedAttributes) > 0 {
		// TODO(fullsailor): First check the content type match
		var digest []byte
		err := unmarshalAttribute(signer.AuthenticatedAttributes, OIDAttributeMessageDigest, &digest)
		if err != nil {
			return err
		}
		hash, err := pkix.GetHashForOID(signer.DigestAlgorithm.Algorithm)
		if err != nil {
			return err
		}
		h := hash.New()
		h.Write(p7.Content)
		computed := h.Sum(nil)
		if subtle.ConstantTimeCompare(digest, computed) != 1 {
			return pkerr.NewErrMessageDigestMismatch()
		}
		signedData, err = marshalAttributes(signer.AuthenticatedAttributes)
		if err != nil {
			return err
		}
		err = unmarshalAttribute(signer.AuthenticatedAttributes, OIDAttributeSigningTime, &signingTime)
		if err == nil {
			// signing time found, performing validity check
			if signingTime.After(ee.NotAfter) || signingTime.Before(ee.NotBefore) {
				return pkerr.NewErrSigningTimeOutOfValidity(
					signingTime.Format(time.RFC3339),
					ee.NotBefore.Format(time.RFC3339),
					ee.NotBefore.Format(time.RFC3339))
			}
		}
	}
	if truststore != nil {
		_, err = verifyCertChain(ee, p7.Certificates, truststore, signingTime)
		if err != nil {
			return err
		}
	}
	sigalg, err := pkix.GetSignatureAlgorithm(signer.DigestEncryptionAlgorithm, signer.DigestAlgorithm)
	if err != nil {
		return err
	}
	return ee.CheckSignature(sigalg, signedData, signer.EncryptedDigest)
}

// GetOnlySigner returns an x509.Certificate for the first signer of the signed
// data payload. If there are more or less than one signer, nil is returned
func (p7 *PKCS7) GetOnlySigner() *x509.Certificate {
	if len(p7.Signers) != 1 {
		return nil
	}
	signer := p7.Signers[0]
	return getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
}

// UnmarshalSignedAttribute decodes a single attribute from the signer info
func (p7 *PKCS7) UnmarshalSignedAttribute(attributeType asn1.ObjectIdentifier, out interface{}) pkerr.Kerror {
	sd, ok := p7.raw.(signedData)
	if !ok {
		return pkerr.NewErrMsgHasNoSignedContent()
	}
	if len(sd.SignerInfos) < 1 {
		return pkerr.NewErrMsgWithoutSigners()
	}
	attributes := sd.SignerInfos[0].AuthenticatedAttributes
	return unmarshalAttribute(attributes, attributeType, out)
}

// verifyCertChain takes an end-entity certs, a list of potential intermediates and a
// truststore, and built all potential chains between the EE and a trusted root.
//
// When verifying chains that may have expired, currentTime can be set to a past date
// to allow the verification to pass. If unset, currentTime is set to the current UTC time.
func verifyCertChain(ee *x509.Certificate, certs []*x509.Certificate, truststore *x509.CertPool, currentTime time.Time) (chains [][]*x509.Certificate, err pkerr.Kerror) {
	intermediates := x509.NewCertPool()
	for _, intermediate := range certs {
		intermediates.AddCert(intermediate)
	}
	verifyOptions := x509.VerifyOptions{
		Roots:         truststore,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   currentTime,
	}
	chains, err = ee.Verify(verifyOptions)
	if err != nil {
		return chains, pkerr.NewErrChainVerify(err)
	}
	return
}

func getCertFromCertsByIssuerAndSerial(certs []*x509.Certificate, ias issuerAndSerial) *x509.Certificate {
	for _, cert := range certs {
		if isCertMatchForIssuerAndSerial(cert, ias) {
			return cert
		}
	}
	return nil
}

func unmarshalAttribute(attrs []attribute, attributeType asn1.ObjectIdentifier, out interface{}) pkerr.Kerror {
	for _, attr := range attrs {
		if attr.Type.Equal(attributeType) {
			_, err := asn1.Unmarshal(attr.Value.Bytes, out)
			return err
		}
	}
	return pkerr.NewErrMissingAttributType()
}
