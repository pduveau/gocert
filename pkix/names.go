// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package pkix contains shared, low level structures used for ASN.1 parsing
// and serialization of X.509 certificates, CRL and OCSP.
package pkix

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/pduveau/gocert/asn1"
)

var attributeTypeNames = map[string]string{
	"2.5.4.6":  "C",
	"2.5.4.10": "O",
	"2.5.4.11": "OU",
	"2.5.4.3":  "CN",
	"2.5.4.5":  "SERIALNUMBER",
	"2.5.4.7":  "L",
	"2.5.4.8":  "ST",
	"2.5.4.9":  "STREET",
	"2.5.4.17": "POSTALCODE",
}

func extendedTypeToString(v any) string {
	switch c := v.(type) {
	case asn1.UTF8String:
		return string(c)
	case asn1.IA5String:
		return string(c)
	case asn1.NUMERICString:
		return string(c)
	case asn1.T61String:
		return string(c)
	case asn1.BMPString:
		return string(c)
	case string:
		return c
	}
	return ""
}

func prefixToType(v string) any {
	splitValue := strings.SplitN(v, ":", 2)
	if len(splitValue) == 2 {
		switch splitValue[0] {
		case "utf8":
			return asn1.UTF8String(splitValue[1])
		case "ia5":
			return asn1.IA5String(splitValue[1])
		case "numeric":
			return asn1.NUMERICString(splitValue[1])
		case "t61":
			return asn1.T61String(splitValue[1])
		case "bmp":
			return asn1.BMPString(splitValue[1])
		}
	}
	return v
}

type RDNSequence []RelativeDistinguishedNameSET

type RelativeDistinguishedNameSET []AttributeTypeAndValue

// AttributeTypeAndValue mirrors the ASN.1 structure of the same name in
// RFC 5280, Section 4.1.2.4.
type AttributeTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value any
}

// String returns a string representation of the sequence r,
// roughly following the RFC 2253 Distinguished Names syntax.
func (r RDNSequence) String() string {
	s := ""
	for i, rdn := range r {
		if i > 0 {
			s += ","
		}
		for j, tv := range rdn {
			if j > 0 {
				s += "+"
			}

			oidString := tv.Type.String()
			typeName, ok := attributeTypeNames[oidString]
			if !ok {
				derBytes, err := asn1.Marshal(tv.Value)
				if err == nil {
					s += oidString + "=#" + hex.EncodeToString(derBytes)
					continue // No value escaping necessary.
				}

				typeName = oidString
			}

			valueString := fmt.Sprint(tv.Value)
			escaped := make([]rune, 0, len(valueString))

			for k, c := range valueString {
				escape := false

				switch c {
				case ',', '+', '"', '\\', '<', '>', ';':
					escape = true

				case ' ':
					escape = k == 0 || k == len(valueString)-1

				case '#':
					escape = k == 0
				}

				if escape {
					escaped = append(escaped, '\\', c)
				} else {
					escaped = append(escaped, c)
				}
			}

			s += typeName + "=" + string(escaped)
		}
	}

	return s
}

// Name represents an X.509 distinguished name. This only includes the common
// elements of a DN. Note that Name is only an approximation of the X.509
// structure. If an accurate representation is needed, asn1.Unmarshal the raw
// subject or issuer as an [RDNSequence].
type Name struct {
	Country, Organization, OrganizationalUnit       []string
	Locality, Province, CommonName                  []string
	StreetAddress, PostalCode, Uid, DomainComponent []string

	// Names contains attributes to be copied, raw, into any marshaled
	// distinguished names. Values override any attributes with the same OID.
	// The Names field is not populated when parsing, see Names.
	Names []AttributeTypeAndValue
}

func (n *Name) setField(t asn1.ObjectIdentifier, value string) {
	if len(t) == 4 && t[0] == 2 && t[1] == 5 && t[2] == 4 {
		switch t[3] {
		case 3:
			n.CommonName = append(n.CommonName, value)
		case 6:
			n.Country = append(n.Country, value)
		case 7:
			n.Locality = append(n.Locality, value)
		case 8:
			n.Province = append(n.Province, value)
		case 9:
			n.StreetAddress = append(n.StreetAddress, value)
		case 10:
			n.Organization = append(n.Organization, value)
		case 11:
			n.OrganizationalUnit = append(n.OrganizationalUnit, value)
		case 17:
			n.PostalCode = append(n.PostalCode, value)
		}
	} else {
		if len(t) == 7 && slices.Equal(t[:6], OidUniqueID[:6]) {
			switch t[6] {
			case 1:
				n.Uid = append(n.Uid, value)
			case 25:
				n.DomainComponent = append(n.DomainComponent, value)
			}
		}
	}

}

// FillFromRDNSequence populates n from the provided [RDNSequence].
// Multi-entry RDNs are flattened, all entries are added to the
// relevant n fields, and the grouping is not preserved.
func (n *Name) FillFromRDNSequence(rdns *RDNSequence) {
	for _, rdn := range *rdns {
		if len(rdn) == 0 {
			continue
		}

		for _, atv := range rdn {
			n.Names = append(n.Names, atv)
			value := extendedTypeToString(atv.Value)
			if value == "" {
				continue
			}

			n.setField(atv.Type, value)
		}
	}
}

var (
	OidCountry            = asn1.ObjectIdentifier{2, 5, 4, 6}
	OidOrganization       = asn1.ObjectIdentifier{2, 5, 4, 10}
	OidOrganizationalUnit = asn1.ObjectIdentifier{2, 5, 4, 11}
	OidCommonName         = asn1.ObjectIdentifier{2, 5, 4, 3}
	OidSerialNumber       = asn1.ObjectIdentifier{2, 5, 4, 5}
	OidLocality           = asn1.ObjectIdentifier{2, 5, 4, 7}
	OidProvince           = asn1.ObjectIdentifier{2, 5, 4, 8}
	OidStreetAddress      = asn1.ObjectIdentifier{2, 5, 4, 9}
	OidPostalCode         = asn1.ObjectIdentifier{2, 5, 4, 17}
	OidUniqueID           = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}
	OidDomainComponent    = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
)

// ToRDNSequence converts n into a single [RDNSequence].
func (n Name) ToRDNSequence() (ret RDNSequence) {
	for _, atv := range n.Names {
		ret = append(ret, []AttributeTypeAndValue{atv})
	}
	return ret
}

// String returns the string form of Name.
func (n Name) String() string {
	return n.ToRDNSequence().String()
}

func (n Name) AppendRDN(oid asn1.ObjectIdentifier, value any) Name {
	var str string
	if v, ok := value.(string); ok {
		value = prefixToType(v)
	}
	str = extendedTypeToString(value)
	n.Names = append(n.Names, AttributeTypeAndValue{
		Type:  oid,
		Value: value,
	})
	if str != "" {
		n.setField(oid, str)
	}
	return n
}
