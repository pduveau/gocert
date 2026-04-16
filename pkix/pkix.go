// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package pkix contains shared, low level structures used for ASN.1 parsing
// and serialization of X.509 certificates, CRL and OCSP.
package pkix

import (
	"fmt"
	"slices"

	"github.com/pduveau/gocert/asn1"
)

// AlgorithmIdentifier represents the ASN.1 structure of the same name. See RFC
// 5280, section 4.1.1.2.
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type AttributeTypeAndValueSET struct {
	Type  asn1.ObjectIdentifier
	Value [][]AttributeTypeAndValue `asn1:"set"`
}

type OtherName struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

func (o *OtherName) Set(value any, oid ...int) (err error) {
	if len(oid) < 4 {
		return fmt.Errorf("The oid is invalid !")
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
		return fmt.Errorf("The oid is invalid !")
	}
	*rid = value
	return nil
}
