// Package pkcs7 implements parsing and generation of some PKCS#7 structures.
package pkcs7

import (
	"bytes"
	"io"
	"sort"

	_ "crypto/sha1" // for crypto.SHA1

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/crl"
	"github.com/pduveau/gocert/pkerr"
	"github.com/pduveau/gocert/x509"
)

// PKCS7 Represents a PKCS7 structure
type PKCS7 struct {
	Content      []byte
	Certificates []*x509.Certificate
	CRLs         []crl.CertificateList
	Signers      []signerInfo
	raw          interface{}
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

var (
	// Signed Data OIDs
	OIDDataContentType               = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDSignedDataContentType         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDEnvelopedDataContentType      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	OIDEncryptedDataContentType      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	OIDAttributeContentType          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDAttributeMessageDigest        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OIDAttributeSigningTime          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	OIDAttributeTimeStampToken       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}
	OIDAttributeSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	OIDAttributeAdobeRevocation      = asn1.ObjectIdentifier{1, 2, 840, 113583, 1, 1, 8}

	// Decryption only Algorithms for compatibility
	oidDecryptionAlgorithmDESCBC     = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7}
	oidDecryptionAlgorithmDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
)

// Parse decodes a DER encoded PKCS7 package
func Parse(data []byte) (p7 *PKCS7, err pkerr.Kerror) {
	if len(data) == 0 {
		return nil, pkerr.NewErrEmptyInputData()
	}
	var info contentInfo
	der, err := ber2der(data)
	if err != nil && err != io.EOF {
		return nil, err
	}
	rest, err := asn1.Unmarshal(der, &info)
	if len(rest) > 0 {
		err = pkerr.NewErrAsn1Syntax("trailing data")
		return
	}
	if err != nil {
		return
	}

	// fmt.Printf("--> Content Type: %s", info.ContentType)
	var pkcs7 PKCS7
	switch {
	case info.ContentType.Equal(OIDSignedDataContentType):
		pkcs7.parseSignedData(info.Content.Bytes)
	case info.ContentType.Equal(OIDEnvelopedDataContentType):
		pkcs7.parseEnvelopedData(info.Content.Bytes)
	case info.ContentType.Equal(OIDEncryptedDataContentType):
		pkcs7.parseEncryptedData(info.Content.Bytes)
	default:
		return nil, pkerr.NewErrUnsupportedContentType()
	}
	return &pkcs7, nil
}

func (pkcs7 *PKCS7) parseEnvelopedData(data []byte) (err pkerr.Kerror) {
	var ed envelopedData
	_, err = asn1.Unmarshal(data, &ed)
	if err == nil {
		pkcs7.raw = ed
	}
	return
}

func (pkcs7 *PKCS7) parseEncryptedData(data []byte) (err pkerr.Kerror) {
	var ed encryptedData
	_, err = asn1.Unmarshal(data, &ed)
	if err == nil {
		pkcs7.raw = ed
	}
	return
}

func (pkcs7 *PKCS7) parseSignedData(data []byte) (err pkerr.Kerror) {
	var sd signedData
	_, err = asn1.Unmarshal(data, &sd)
	if err != nil {
		return
	}
	pkcs7.Certificates, err = sd.Certificates.Parse()
	if err != nil {
		return
	}
	// fmt.Printf("--> Signed Data Version %d\n", sd.Version)

	var compound asn1.RawValue

	// The Content.Bytes maybe empty on PKI responses.
	if len(sd.ContentInfo.Content.Bytes) > 0 {
		_, err = asn1.Unmarshal(sd.ContentInfo.Content.Bytes, &compound)
		if err != nil {
			return
		}
	}
	// Compound octet string
	if compound.IsCompound {
		if compound.Tag == 4 {
			_, err = asn1.Unmarshal(compound.Bytes, &pkcs7.Content)
			if err != nil {
				return
			}
		} else {
			pkcs7.Content = compound.Bytes
		}
	} else {
		// assuming this is tag 04
		pkcs7.Content = compound.Bytes
	}
	pkcs7.CRLs = sd.CRLs
	pkcs7.Signers = sd.SignerInfos
	pkcs7.raw = sd
	return
}

func (raw rawCertificates) Parse() ([]*x509.Certificate, pkerr.Kerror) {
	if len(raw.Raw) == 0 {
		return nil, nil
	}

	var val asn1.RawValue
	if _, err := asn1.Unmarshal(raw.Raw, &val); err != nil {
		return nil, err
	}

	return x509.ParseCertificates(val.Bytes)
}

func isCertMatchForIssuerAndSerial(cert *x509.Certificate, ias issuerAndSerial) bool {
	return cert.SerialNumber.Cmp(ias.SerialNumber) == 0 && bytes.Equal(cert.RawIssuer, ias.IssuerName.FullBytes)
}

// Attribute represents a key value pair attribute. Value must be marshalable byte
// `encoding/asn1`
type Attribute struct {
	Type  asn1.ObjectIdentifier
	Value interface{}
}

type attributes struct {
	types  []asn1.ObjectIdentifier
	values []interface{}
}

// Add adds the attribute, maintaining insertion order
func (attrs *attributes) Add(attrType asn1.ObjectIdentifier, value interface{}) {
	attrs.types = append(attrs.types, attrType)
	attrs.values = append(attrs.values, value)
}

type sortableAttribute struct {
	SortKey   []byte
	Attribute attribute
}

type attributeSet []sortableAttribute

func (sa attributeSet) Len() int {
	return len(sa)
}

func (sa attributeSet) Less(i, j int) bool {
	return bytes.Compare(sa[i].SortKey, sa[j].SortKey) < 0
}

func (sa attributeSet) Swap(i, j int) {
	sa[i], sa[j] = sa[j], sa[i]
}

func (sa attributeSet) Attributes() []attribute {
	attrs := make([]attribute, len(sa))
	for i, attr := range sa {
		attrs[i] = attr.Attribute
	}
	return attrs
}

func (attrs *attributes) ForMarshalling() ([]attribute, pkerr.Kerror) {
	sortables := make(attributeSet, len(attrs.types))
	for i := range sortables {
		attrType := attrs.types[i]
		attrValue := attrs.values[i]
		asn1Value, err := asn1.Marshal(attrValue)
		if err != nil {
			return nil, err
		}
		attr := attribute{
			Type:  attrType,
			Value: asn1.RawValue{Tag: 17, IsCompound: true, Bytes: asn1Value}, // 17 == SET tag
		}
		encoded, err := asn1.Marshal(attr)
		if err != nil {
			return nil, err
		}
		sortables[i] = sortableAttribute{
			SortKey:   encoded,
			Attribute: attr,
		}
	}
	sort.Sort(sortables)
	return sortables.Attributes(), nil
}
