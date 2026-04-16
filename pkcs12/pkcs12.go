// Copyright 2015, 2018, 2019 Opsmate, Inc. All rights reserved.
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package pkcs12 implements some of PKCS#12 (also known as P12 or PFX).
// It is intended for decoding DER-encoded P12/PFX files for use with the crypto/tls
// package, and for encoding P12/PFX files for use by legacy applications which
// do not support newer formats.  Since PKCS#12 uses weak encryption
// primitives, it SHOULD NOT be used for new applications.
//
// Note that only DER-encoded PKCS#12 files are supported, even though PKCS#12
// allows BER encoding.  This is because encoding/asn1 only supports DER.
//
// This package is forked from golang.org/x/crypto/pkcs12, which is frozen.
// The implementation is distilled from https://tools.ietf.org/html/rfc7292
// and referenced documents.
package pkcs12

import (
	"crypto/rand"
	"fmt"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/pkcs5"
	"github.com/pduveau/gocert/pkcs7"
	"github.com/pduveau/gocert/pkcs8"
	"github.com/pduveau/gocert/pkix"
	"github.com/pduveau/gocert/x509"
)

// DefaultPassword is the string "changeit", a commonly-used password for
// PKCS#12 files.
const DefaultPassword = "changeit"

var SaltLen = 16
var Iterations = 2048

var (
	// ErrDecryption represents a failure to decrypt the input.
	ErrDecryption = fmt.Errorf("pkcs12: decryption error, incorrect padding")

	// ErrIncorrectPassword is returned when an incorrect password is detected.
	// Usually, P12/PFX data is signed to be able to verify the password.
	ErrIncorrectPassword = fmt.Errorf("pkcs12: decryption password incorrect")
)

// NotImplementedError indicates that the input is not currently supported.
type NotImplementedError string

func (e NotImplementedError) Error() string {
	return "pkcs12: " + string(e)
}

var (
	oidDataContentType     = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 7, 1})
	oidJavaTrustStore      = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 113894, 746875, 1, 1})
	oidAnyExtendedKeyUsage = asn1.ObjectIdentifier([]int{2, 5, 29, 37, 0})
)

type pfxPdu struct {
	Version  int
	AuthSafe contentInfo
	MacData  macData `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

type pkcs12Attribute struct {
	Id    asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type encryptedPrivateKeyInfo struct {
	AlgorithmIdentifier pkix.AlgorithmIdentifier
	EncryptedData       []byte
}

func (i encryptedPrivateKeyInfo) Algorithm() pkix.AlgorithmIdentifier {
	return i.AlgorithmIdentifier
}

func (i encryptedPrivateKeyInfo) Data() []byte {
	return i.EncryptedData
}

func (i *encryptedPrivateKeyInfo) SetData(data []byte) {
	i.EncryptedData = data
}

// Decode extracts a certificate and private key from pfxData, which must be a DER-encoded PKCS#12 file. This function
// assumes that there is only one certificate and only one private key in the
// pfxData.  Since PKCS#12 files often contain more than one certificate, you
// probably want to use [DecodeChain] instead.
func Decode(pfxData []byte, password string) (privateKey interface{}, certificate *x509.Certificate, err error) {
	var caCerts []*x509.Certificate
	privateKey, certificate, caCerts, err = DecodeChain(pfxData, password)
	if len(caCerts) != 0 {
		err = fmt.Errorf("pkcs12: expected exactly two safe bags in the PFX PDU")
	}
	return
}

// DecodeChain extracts a certificate, a CA certificate chain, and private key
// from pfxData, which must be a DER-encoded PKCS#12 file. This function assumes that there is at least one certificate
// and only one private key in the pfxData.  The first certificate is assumed to
// be the leaf certificate, and subsequent certificates, if any, are assumed to
// comprise the CA certificate chain.
func DecodeChain(pfxData []byte, password string) (privateKey interface{}, certificate *x509.Certificate, caCerts []*x509.Certificate, err error) {
	encodedPassword, err := bmpStringZeroTerminated(password)
	if err != nil {
		return nil, nil, nil, err
	}

	bags, encodedPassword, err := getSafeContents(pfxData, encodedPassword, 1, 2)
	if err != nil {
		return nil, nil, nil, err
	}

	for _, bag := range bags {
		switch {
		case bag.Id.Equal(oidCertBag):
			certsData, err := decodeCertBag(bag.Value.Bytes)
			if err != nil {
				return nil, nil, nil, err
			}
			certs, err := x509.ParseCertificates(certsData)
			if err != nil {
				return nil, nil, nil, err
			}
			if len(certs) != 1 {
				err = fmt.Errorf("pkcs12: expected exactly one certificate in the certBag")
				return nil, nil, nil, err
			}
			if certificate == nil {
				certificate = certs[0]
			} else {
				caCerts = append(caCerts, certs[0])
			}

		case bag.Id.Equal(oidKeyBag):
			if privateKey != nil {
				err = fmt.Errorf("pkcs12: expected exactly one key bag")
				return nil, nil, nil, err
			}

			if privateKey, err = pkcs8.ParsePKCS8PrivateKey(bag.Value.Bytes); err != nil {
				return nil, nil, nil, err
			}
		case bag.Id.Equal(oidPKCS8ShroundedKeyBag):
			if privateKey != nil {
				err = fmt.Errorf("pkcs12: expected exactly one key bag")
				return nil, nil, nil, err
			}

			originalPassword, err := decodeBMPString(encodedPassword)
			if err != nil {
				return nil, nil, nil, err
			}
			privateKey, _, err = pkcs8.ParsePKCS8EncryptedPrivateKey(bag.Value.Bytes, []byte(originalPassword))
			if err != nil {
				return nil, nil, nil, err
			}
		}
	}

	if certificate == nil {
		return nil, nil, nil, fmt.Errorf("pkcs12: certificate missing")
	}
	if privateKey == nil {
		return nil, nil, nil, fmt.Errorf("pkcs12: private key missing")
	}

	return
}

// DecodeTrustStore extracts the certificates from pfxData, which must be a DER-encoded
// PKCS#12 file containing exclusively certificates with attribute 2.16.840.1.113894.746875.1.1,
// which is used by Java to designate a trust anchor.
//
// If the password argument is empty, DecodeTrustStore will decode either password-less
// PKCS#12 files (i.e. those without encryption) or files with a literal empty password.
func DecodeTrustStore(pfxData []byte, password string) (certs []*x509.Certificate, err error) {
	encodedPassword, err := bmpStringZeroTerminated(password)
	if err != nil {
		return nil, err
	}

	bags, encodedPassword, err := getSafeContents(pfxData, encodedPassword, 1, 1)
	if err != nil {
		return nil, err
	}

	for _, bag := range bags {
		switch {
		case bag.Id.Equal(oidCertBag):
			if !bag.hasAttribute(oidJavaTrustStore) {
				return nil, fmt.Errorf("pkcs12: trust store contains a certificate that is not marked as trusted")
			}
			certsData, err := decodeCertBag(bag.Value.Bytes)
			if err != nil {
				return nil, err
			}
			parsedCerts, err := x509.ParseCertificates(certsData)
			if err != nil {
				return nil, err
			}

			if len(parsedCerts) != 1 {
				err = fmt.Errorf("pkcs12: expected exactly one certificate in the certBag")
				return nil, err
			}

			certs = append(certs, parsedCerts[0])

		default:
			return nil, fmt.Errorf("pkcs12: expected only certificate bags")
		}
	}

	return
}

func getSafeContents(p12Data, password []byte, expectedItemsMin int, expectedItemsMax int) (bags []safeBag, updatedPassword []byte, err error) {
	pfx := &pfxPdu{}
	if err := unmarshal(p12Data, pfx); err != nil {
		return nil, nil, fmt.Errorf("pkcs12: error reading P12 data: %v", err)
	}

	if pfx.Version != 3 {
		return nil, nil, fmt.Errorf("pkcs12: can only decode v3 PFX PDU's")
	}

	if !pfx.AuthSafe.ContentType.Equal(pkcs7.OIDDataContentType) {
		return nil, nil, fmt.Errorf("pkcs12: only password-protected PFX is implemented")
	}

	// unmarshal the explicit bytes in the content for type 'data'
	if err := unmarshal(pfx.AuthSafe.Content.Bytes, &pfx.AuthSafe.Content); err != nil {
		return nil, nil, err
	}

	if len(pfx.MacData.Mac.Algorithm.Algorithm) == 0 {
		return nil, nil, fmt.Errorf("pkcs12: no MAC in data")
	} else if err := verifyMac(&pfx.MacData, pfx.AuthSafe.Content.Bytes, password); err != nil {
		return nil, nil, err
	}

	var authenticatedSafe []contentInfo
	if err := unmarshal(pfx.AuthSafe.Content.Bytes, &authenticatedSafe); err != nil {
		return nil, nil, err
	}

	if len(authenticatedSafe) < expectedItemsMin || len(authenticatedSafe) > expectedItemsMax {
		if expectedItemsMin == expectedItemsMax {
			return nil, nil, fmt.Errorf("pkcs12: expected exactly %d items in the authenticated safe, but this file has %d", expectedItemsMin, len(authenticatedSafe))
		}
		return nil, nil, fmt.Errorf("pkcs12: expected between %d and %d items in the authenticated safe, but this file has %d", expectedItemsMin, expectedItemsMax, len(authenticatedSafe))
	}

	for _, ci := range authenticatedSafe {
		var data []byte

		switch {
		case ci.ContentType.Equal(pkcs7.OIDDataContentType):
			if err := unmarshal(ci.Content.Bytes, &data); err != nil {
				return nil, nil, err
			}
		case ci.ContentType.Equal(pkcs7.OIDEncryptedDataContentType):
			var encryptedData encryptedData
			if err := unmarshal(ci.Content.Bytes, &encryptedData); err != nil {
				return nil, nil, err
			}
			if encryptedData.Version != 0 {
				return nil, nil, fmt.Errorf("pkcs12: only version 0 of EncryptedData is supported")
			}
			originalPassword, err := decodeBMPString(password)
			if err != nil {
				return nil, nil, err
			}
			data, _, err = pkcs5.ParseEncryptedPKCS5(encryptedData.EncryptedContentInfo.ContentEncryptionAlgorithm,
				encryptedData.EncryptedContentInfo.EncryptedContent, []byte(originalPassword))
			if err != nil {
				return nil, nil, err
			}
		default:
			return nil, nil, fmt.Errorf("pkcs12: only data and encryptedData content types are supported in authenticated safe")
		}

		var safeContents []safeBag
		if err := unmarshal(data, &safeContents); err != nil {
			return nil, nil, err
		}
		bags = append(bags, safeContents...)
	}

	return bags, password, nil
}

// Encode produces pfxData containing one private key (privateKey), an
// end-entity certificate (certificate), and any number of CA certificates
// (caCerts).
//
// The pfxData is encrypted and authenticated with keys derived from
// the provided password.
//
// Encode emulates the behavior of OpenSSL's PKCS12_create: it creates two
// SafeContents: one that's encrypted with the certificate encryption algorithm
// and contains the certificates, and another that is unencrypted and contains the
// private key shrouded with the key encryption algorithm.  The private key bag and
// the end-entity certificate bag have the LocalKeyId attribute set to the SHA-1
// fingerprint of the end-entity certificate.
func Encode(pbmac1 bool, privateKey interface{}, certificate *x509.Certificate, caCerts []*x509.Certificate, password string) (pfxData []byte, err error) {
	if password == "" {
		return nil, fmt.Errorf("pkcs12: password must not be empty")
	}

	encodedPassword, err := bmpStringZeroTerminated(password)
	if err != nil {
		return nil, err
	}

	var pfx pfxPdu
	pfx.Version = 3

	var certBags []safeBag
	var certBag safeBag

	localKeyIdAttr, err := certBag.makeCertBag(certificate.Raw, LOCALKEYID, "")
	if err != nil {
		return nil, err
	} else {
		certBags = append(certBags, certBag)
	}

	for _, cert := range caCerts {
		var certBag safeBag
		if _, err := certBag.makeCertBag(cert.Raw, 0, ""); err != nil {
			return nil, err
		} else {
			certBags = append(certBags, certBag)
		}
	}

	var shroudedKey []byte
	opts := pkcs5.NewDefaultOpts()
	opts.SaltSize = SaltLen
	opts.KDFParams.SetIterations(Iterations)

	originalPassword, err := decodeBMPString(encodedPassword)
	if err != nil {
		return nil, err
	}
	shroudedKey, err = pkcs8.MarshalPKCS8EncryptedPrivateKey(privateKey, []byte(originalPassword), opts)

	if err != nil {
		return nil, err
	}

	var keyBag = safeBag{
		Id: oidPKCS8ShroundedKeyBag,
		Value: asn1.RawValue{
			Class:      2,
			Tag:        0,
			IsCompound: true,
			Bytes:      shroudedKey,
		},
	}

	keyBag.Attributes = append(keyBag.Attributes, *localKeyIdAttr)

	// Construct an authenticated safe with two SafeContents.
	// The first SafeContents is encrypted and contains the cert bags.
	// The second SafeContents is unencrypted and contains the shrouded key bag.
	var authenticatedSafe [2]contentInfo
	if authenticatedSafe[0], err = makeSafeContents(certBags, encodedPassword); err != nil {
		return nil, err
	}
	if authenticatedSafe[1], err = makeSimpleContents([]safeBag{keyBag}); err != nil {
		return nil, err
	}

	var authenticatedSafeBytes []byte
	if authenticatedSafeBytes, err = asn1.Marshal(authenticatedSafe[:]); err != nil {
		return nil, err
	}

	if pbmac1 {
		opts := pkcs5.NewDefaultPBMAC1Opts()
		opts.KDFParams.SetIterations(Iterations)
		opts.KDFParams.SetKeyLength(32)
		opts.KDFParams.MakeSalt(SaltLen)

		pbes2, _, err := pkcs5.MakePBES2(opts)
		if err != nil {
			return nil, err
		}

		pfx.MacData.Mac.Algorithm = *pbes2
	} else {
		macSalt := make([]byte, SaltLen)
		if _, err = rand.Read(macSalt); err != nil {
			return nil, err
		}
		pfx.MacData.MacSalt = macSalt
		pfx.MacData.Iterations = Iterations
		pfx.MacData.Mac.Algorithm.Algorithm = oidSHA256
	}

	fmt.Printf("%v", pfx.MacData)

	if err = computeMac(&pfx.MacData, authenticatedSafeBytes, encodedPassword); err != nil {
		return nil, err
	}

	pfx.AuthSafe.ContentType = pkcs7.OIDDataContentType
	pfx.AuthSafe.Content.Class = 2
	pfx.AuthSafe.Content.Tag = 0
	pfx.AuthSafe.Content.IsCompound = true
	if pfx.AuthSafe.Content.Bytes, err = asn1.Marshal(authenticatedSafeBytes); err != nil {
		return nil, err
	}

	if pfxData, err = asn1.Marshal(pfx); err != nil {
		return nil, fmt.Errorf("pkcs12: error writing P12 data: %v", err)
	}
	return
}

// EncodeTrustStore produces pfxData containing any number of CA certificates
// (certs) to be trusted. The certificates will be marked with a special OID that
// allow it to be used as a Java TrustStore in Java 1.8 and newer.
//
// EncodeTrustStore creates a single SafeContents that's optionally encrypted
// and contains the certificates.
//
// The Subject of the certificates are used as the Friendly Names (Aliases)
// within the resulting pfxData. If certificates share a Subject, then the
// resulting Friendly Names (Aliases) will be identical, which Java may treat as
// the same entry when used as a Java TrustStore, e.g. with `keytool`.  To
// customize the Friendly Names, use [EncodeTrustStoreEntries].
func EncodeTrustStore(certs []*x509.Certificate, password string) (pfxData []byte, err error) {
	var certsWithFriendlyNames []TrustStoreEntry
	for _, cert := range certs {
		certsWithFriendlyNames = append(certsWithFriendlyNames, TrustStoreEntry{
			Cert:         cert,
			FriendlyName: cert.Subject.String(),
		})
	}
	return EncodeTrustStoreEntries(certsWithFriendlyNames, password)
}

// TrustStoreEntry represents an entry in a Java TrustStore.
type TrustStoreEntry struct {
	Cert         *x509.Certificate
	FriendlyName string
}

// EncodeTrustStoreEntries produces pfxData containing any number of CA
// certificates (entries) to be trusted. The certificates will be marked with a
// special OID that allow it to be used as a Java TrustStore in Java 1.8 and newer.
//
// This is identical to [Encoder.EncodeTrustStore], but also allows for setting specific
// Friendly Names (Aliases) to be used per certificate, by specifying a slice
// of TrustStoreEntry.
//
// If the same Friendly Name is used for more than one certificate, then the
// resulting Friendly Names (Aliases) in the pfxData will be identical, which Java
// may treat as the same entry when used as a Java TrustStore, e.g. with `keytool`.
//
// EncodeTrustStoreEntries creates a single SafeContents that's optionally
// encrypted and contains the certificates.
func EncodeTrustStoreEntries(entries []TrustStoreEntry, password string) (pfxData []byte, err error) {
	if password == "" {
		return nil, fmt.Errorf("pkcs12: password must NOT be empty")
	}

	encodedPassword, err := bmpStringZeroTerminated(password)
	if err != nil {
		return nil, err
	}

	var pfx pfxPdu
	pfx.Version = 3

	var certBags []safeBag
	for _, entry := range entries {
		var certBag safeBag
		_, err = certBag.makeCertBag(entry.Cert.Raw, JAVATRUSTSTORE, entry.FriendlyName)
		if err != nil {
			return nil, err
		}
		certBags = append(certBags, certBag)
	}

	// Construct an authenticated safe with one SafeContent.
	// The SafeContents is contains the cert bags.
	var authenticatedSafe [1]contentInfo
	if authenticatedSafe[0], err = makeSafeContents(certBags, encodedPassword); err != nil {
		return nil, err
	}

	var authenticatedSafeBytes []byte
	if authenticatedSafeBytes, err = asn1.Marshal(authenticatedSafe[:]); err != nil {
		return nil, err
	}

	// compute the MAC
	//if pbmac1 {
	//	pfx.MacData.Mac.Algorithm.Algorithm = oidPBMAC1
	//} else {
	pfx.MacData.Mac.Algorithm.Algorithm = oidSHA256
	//}
	pfx.MacData.MacSalt = make([]byte, SaltLen)
	if _, err = rand.Read(pfx.MacData.MacSalt); err != nil {
		return nil, err
	}
	pfx.MacData.Iterations = Iterations
	if err = computeMac(&pfx.MacData, authenticatedSafeBytes, encodedPassword); err != nil {
		return nil, err
	}

	pfx.AuthSafe.ContentType = pkcs7.OIDDataContentType
	pfx.AuthSafe.Content.Class = 2
	pfx.AuthSafe.Content.Tag = 0
	pfx.AuthSafe.Content.IsCompound = true
	if pfx.AuthSafe.Content.Bytes, err = asn1.Marshal(authenticatedSafeBytes); err != nil {
		return nil, err
	}

	if pfxData, err = asn1.Marshal(pfx); err != nil {
		return nil, fmt.Errorf("pkcs12: error writing P12 data: %v", err)
	}
	return
}

func makeSafeContents(bags []safeBag, password []byte) (ci contentInfo, err error) {
	var data []byte
	if data, err = asn1.Marshal(bags); err != nil {
		return
	}

	var algo = &pkix.AlgorithmIdentifier{}
	var encryptedData encryptedData

	opts := pkcs5.NewDefaultOpts()
	opts.KDFParams.MakeSalt(SaltLen)
	opts.KDFParams.SetIterations(Iterations)

	originalPassword, err := decodeBMPString(password)
	if err != nil {
		return
	}
	algo, encryptedData.EncryptedContentInfo.EncryptedContent, err = pkcs5.MarshalEncryptedPKCS5(data, []byte(originalPassword), opts)
	if err != nil {
		return
	}
	encryptedData.EncryptedContentInfo.ContentType = oidDataContentType
	encryptedData.EncryptedContentInfo.ContentEncryptionAlgorithm = *algo

	ci.ContentType = pkcs7.OIDEncryptedDataContentType
	ci.Content.Class = 2
	ci.Content.Tag = 0
	ci.Content.IsCompound = true
	ci.Content.Bytes, err = asn1.Marshal(encryptedData)

	return
}

func makeSimpleContents(bags []safeBag) (ci contentInfo, err error) {
	var data []byte
	if data, err = asn1.Marshal(bags); err != nil {
		return
	}

	ci.ContentType = oidDataContentType
	ci.Content.Class = 2
	ci.Content.Tag = 0
	ci.Content.IsCompound = true
	ci.Content.Bytes, err = asn1.Marshal(data)
	return
}
