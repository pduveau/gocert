// Copyright 2015, 2018, 2019 Opsmate, Inc. All rights reserved.
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"crypto/sha1"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/pkerr"
	"github.com/pduveau/gocert/pkix"
)

var (
	// see https://tools.ietf.org/html/rfc7292#appendix-D
	oidCertTypeX509Certificate = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 22, 1})
	oidKeyBag                  = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 1})
	oidPKCS8ShroundedKeyBag    = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 2})
	oidCertBag                 = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 3})
)

type safeBag struct {
	Id         asn1.ObjectIdentifier
	Value      asn1.RawValue     `asn1:"tag:0,explicit"`
	Attributes []pkcs12Attribute `asn1:"set,optional"`
}

func (bag *safeBag) hasAttribute(id asn1.ObjectIdentifier) bool {
	for _, attr := range bag.Attributes {
		if attr.Id.Equal(id) {
			return true
		}
	}
	return false
}

func (bag *safeBag) getFriendlyName() string {
	for _, attr := range bag.Attributes {
		if attr.Id.Equal(oidFriendlyName) {
			_, val, _ := convertAttribute(&attr)
			return val
		}
	}
	return ""
}

const LOCALKEYID = 0x01
const JAVATRUSTSTORE = 0x02

func (bag *safeBag) makeCertBag(certBytes []byte, options int, friendlyName string) (keyId *pkcs12Attribute, err pkerr.Kerror) {
	type DataAttr struct {
		id  asn1.ObjectIdentifier
		val []byte
	}

	var attrs = make([]DataAttr, 0)

	if (options & LOCALKEYID) != 0 {
		var encoded []byte
		var certFingerprint = sha1.Sum(certBytes)
		if encoded, err = asn1.Marshal(certFingerprint[:]); err != nil {
			return
		}
		attrs = append(attrs, DataAttr{oidLocalKeyID, encoded})
	}

	if (options & JAVATRUSTSTORE) != 0 {
		var encoded []byte
		if encoded, err = asn1.Marshal(oidAnyExtendedKeyUsage); err != nil {
			return
		}
		attrs = append(attrs, DataAttr{oidJavaTrustStore, encoded})
	}

	if friendlyName != "" {
		var encoded []byte
		encoded, err = asn1.Marshal(asn1.BMPString(friendlyName))
		if err != nil {
			return
		}
		attrs = append(attrs, DataAttr{oidFriendlyName, encoded})

	}

	var attributes = []pkcs12Attribute{}
	for i, v := range attrs {
		attr := pkcs12Attribute{
			Id: v.id,
			Value: asn1.RawValue{
				Class:      0,
				Tag:        17,
				IsCompound: true,
				Bytes:      v.val,
			},
		}
		if i == 0 && (options&LOCALKEYID) != 0 {
			keyId = &attr
		}
		attributes = append(attributes, attr)
	}

	var b []byte
	if b, err = encodeCertBag(certBytes); err == nil {
		*bag = safeBag{
			Id: oidCertBag,
			Value: asn1.RawValue{
				Class:      2,
				Tag:        0,
				IsCompound: true,
				Bytes:      b,
			},
			Attributes: attributes,
		}
	}
	return
}

/*
// PEM block types
const (

	certificateType = "CERTIFICATE"
	privateKeyType  = "PRIVATE KEY"

)

	func (bag *safeBag) convertBagPem(password []byte) (*pem.Block, pkerr.Kerror) {
		block := &pem.Block{
			Headers: make(map[string]string),
		}

		for _, attribute := range bag.Attributes {
			k, v, err := convertAttribute(&attribute)
			if err != nil {
				return nil, err
			}
			block.Headers[k] = v
		}

		switch {
		case bag.Id.Equal(oidCertBag):
			block.Type = certificateType
			certsData, err := decodeCertBag(bag.Value.Bytes)
			if err != nil {
				return nil, err
			}
			block.Bytes = certsData
		case bag.Id.Equal(oidPKCS8ShroundedKeyBag):
			block.Type = privateKeyType

			key, _, err := x509.ParsePKCS8EncryptedPrivateKey(bag.Value.Bytes, password)
			if err != nil {
				return nil, err
			}

			switch key := key.(type) {
			case *rsa.PrivateKey:
				block.Bytes = x509.MarshalPKCS1PrivateKey(key)
			case *ecdsa.PrivateKey:
				block.Bytes, err = x509.MarshalECPrivateKey(key)
				if err != nil {
					return nil, err
				}
			default:
				return nil, pkerr.New("pkcs12: found unknown private key type in PKCS#8 wrapping")
			}
		default:
			return nil, pkerr.New("pkcs12: don't know how to convert a safe bag of type %s", bag.Id.String())
		}
		return block, nil
	}
*/
type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           []byte `asn1:"tag:0,optional"`
}

func (i encryptedContentInfo) Algorithm() pkix.AlgorithmIdentifier {
	return i.ContentEncryptionAlgorithm
}

func (i encryptedContentInfo) Data() []byte { return i.EncryptedContent }

func (i *encryptedContentInfo) SetData(data []byte) { i.EncryptedContent = data }

type certBag struct {
	Id   asn1.ObjectIdentifier
	Data []byte `asn1:"tag:0,explicit"`
}

func decodeCertBag(asn1Data []byte) (x509Certificates []byte, err pkerr.Kerror) {
	bag := &certBag{}
	if err := unmarshal(asn1Data, bag, "safebag"); err != nil {
		return nil, pkerr.NewErrDecodingCertBag(err)
	}
	if !bag.Id.Equal(oidCertTypeX509Certificate) {
		return nil, pkerr.NewErrOnlyCertificateInCertBag()
	}
	return bag.Data, nil
}

func encodeCertBag(x509Certificates []byte) (asn1Data []byte, err pkerr.Kerror) {
	var bag certBag
	bag.Id = oidCertTypeX509Certificate
	bag.Data = x509Certificates
	if asn1Data, err = asn1.Marshal(bag); err != nil {
		return nil, pkerr.NewErrEncodingCertBag(err)
	}
	return asn1Data, nil
}
