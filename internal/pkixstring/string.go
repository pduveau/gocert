// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cryptobyte contains types that help with parsing and constructing
// length-prefixed, binary messages, including ASN.1 DER. (The asn1 subpackage
// contains useful ASN.1 constants.)
//
// The String type is for parsing. It wraps a []byte slice and provides helper
// functions for consuming structures, value by value.
//
// The Builder type is for constructing messages. It providers helper functions
// for appending values and also for appending length-prefixed submessages –
// without having to worry about calculating the length prefix ahead of time.
//
// See the documentation and examples for the Builder and String types to get
// started.
package pkixstring

import (
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/pkerr"
	"github.com/pduveau/gocert/pkix"
)

// String represents a string of bytes. It provides methods for parsing
// fixed-length and length-prefixed values from it.
type String []byte

// read advances a String by n bytes and returns them. If less than n bytes
// remain, it returns nil.
func (s *String) read(n int) []byte {
	if len(*s) < n || n < 0 {
		return nil
	}
	v := (*s)[:n]
	*s = (*s)[n:]
	return v
}

// Skip advances the String by n byte and reports whether it was successful.
func (s *String) Skip(n int) bool {
	return s.read(n) != nil
}

// ReadUint8 decodes an 8-bit value into out and advances over it.
// It reports whether the read was successful.
func (s *String) ReadUint8(out *uint8) bool {
	v := s.read(1)
	if v == nil {
		return false
	}
	*out = uint8(v[0])
	return true
}

// ReadUint16 decodes a big-endian, 16-bit value into out and advances over it.
// It reports whether the read was successful.
func (s *String) ReadUint16(out *uint16) bool {
	v := s.read(2)
	if v == nil {
		return false
	}
	*out = uint16(v[0])<<8 | uint16(v[1])
	return true
}

// ReadUint24 decodes a big-endian, 24-bit value into out and advances over it.
// It reports whether the read was successful.
func (s *String) ReadUint24(out *uint32) bool {
	v := s.read(3)
	if v == nil {
		return false
	}
	*out = uint32(v[0])<<16 | uint32(v[1])<<8 | uint32(v[2])
	return true
}

// ReadUint32 decodes a big-endian, 32-bit value into out and advances over it.
// It reports whether the read was successful.
func (s *String) ReadUint32(out *uint32) bool {
	v := s.read(4)
	if v == nil {
		return false
	}
	*out = uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
	return true
}

// ReadUint48 decodes a big-endian, 48-bit value into out and advances over it.
// It reports whether the read was successful.
func (s *String) ReadUint48(out *uint64) bool {
	v := s.read(6)
	if v == nil {
		return false
	}
	*out = uint64(v[0])<<40 | uint64(v[1])<<32 | uint64(v[2])<<24 | uint64(v[3])<<16 | uint64(v[4])<<8 | uint64(v[5])
	return true
}

// ReadUint64 decodes a big-endian, 64-bit value into out and advances over it.
// It reports whether the read was successful.
func (s *String) ReadUint64(out *uint64) bool {
	v := s.read(8)
	if v == nil {
		return false
	}
	*out = uint64(v[0])<<56 | uint64(v[1])<<48 | uint64(v[2])<<40 | uint64(v[3])<<32 | uint64(v[4])<<24 | uint64(v[5])<<16 | uint64(v[6])<<8 | uint64(v[7])
	return true
}

func (s *String) readUnsigned(out *uint32, length int) bool {
	v := s.read(length)
	if v == nil {
		return false
	}
	var result uint32
	for i := 0; i < length; i++ {
		result <<= 8
		result |= uint32(v[i])
	}
	*out = result
	return true
}

func (s *String) readLengthPrefixed(lenLen int, outChild *String) bool {
	lenBytes := s.read(lenLen)
	if lenBytes == nil {
		return false
	}
	var length uint32
	for _, b := range lenBytes {
		length = length << 8
		length = length | uint32(b)
	}
	v := s.read(int(length))
	if v == nil {
		return false
	}
	*outChild = v
	return true
}

// ReadUint8LengthPrefixed reads the content of an 8-bit length-prefixed value
// into out and advances over it. It reports whether the read was successful.
func (s *String) ReadUint8LengthPrefixed(out *String) bool {
	return s.readLengthPrefixed(1, out)
}

// ReadUint16LengthPrefixed reads the content of a big-endian, 16-bit
// length-prefixed value into out and advances over it. It reports whether the
// read was successful.
func (s *String) ReadUint16LengthPrefixed(out *String) bool {
	return s.readLengthPrefixed(2, out)
}

// ReadUint24LengthPrefixed reads the content of a big-endian, 24-bit
// length-prefixed value into out and advances over it. It reports whether
// the read was successful.
func (s *String) ReadUint24LengthPrefixed(out *String) bool {
	return s.readLengthPrefixed(3, out)
}

// ReadBytes reads n bytes into out and advances over them. It reports
// whether the read was successful.
func (s *String) ReadBytes(out *[]byte, n int) bool {
	v := s.read(n)
	if v == nil {
		return false
	}
	*out = v
	return true
}

// CopyBytes copies len(out) bytes into out and advances over them. It reports
// whether the copy operation was successful
func (s *String) CopyBytes(out []byte) bool {
	n := len(out)
	v := s.read(n)
	if v == nil {
		return false
	}
	return copy(out, v) == n
}

// Empty reports whether the string does not contain any bytes.
func (s String) Empty() bool {
	return len(s) == 0
}

func (der String) ParseAI() (pkix.AlgorithmIdentifier, pkerr.Kerror) {
	ai := pkix.AlgorithmIdentifier{}
	if !der.ReadASN1ObjectIdentifier(&ai.Algorithm) {
		return ai, pkerr.NewErrInvalidASN1OID()
	}
	if der.Empty() {
		return ai, nil
	}
	var params String
	var tag Tag
	if !der.ReadAnyASN1Element(&params, &tag) {
		return ai, pkerr.NewErrInvalidASN1Params()
	}
	ai.Parameters.Tag = int(tag)
	ai.Parameters.FullBytes = params
	return ai, nil
}

// parseASN1String parses the ASN.1 string types T61String, PrintableString,
// UTF8String, BMPString, IA5String, and NumericString. This is mostly copied
// from the respective encoding/asn1.parse... methods, rather than just
// increasing the API surface of that package.
func (tag Tag) ParseASN1String(value []byte) (any, pkerr.Kerror) {
	switch tag {
	case T61String:
		// T.61 is a defunct ITU 8-bit character encoding which preceded Unicode.
		// T.61 uses a code page layout that _almost_ exactly maps to the code
		// page layout of the ISO 8859-1 (Latin-1) character encoding, with the
		// exception that a number of characters in Latin-1 are not present
		// in T.61.
		//
		// Instead of mapping which characters are present in Latin-1 but not T.61,
		// we just treat these strings as being encoded using Latin-1. This matches
		// what most of the world does, including BoringSSL.
		buf := make([]byte, 0, len(value))
		for _, v := range value {
			// All the 1-byte UTF-8 runes map 1-1 with Latin-1.
			buf = utf8.AppendRune(buf, rune(v))
		}
		return asn1.T61String(buf), nil
	case PrintableString:
		for _, b := range value {
			if !asn1.IsPrintable(b) {
				return "", pkerr.NewErrAsn1Syntax("invalid PrintableString")
			}
		}
		return string(value), nil
	case UTF8String:
		if !utf8.Valid(value) {
			return "", pkerr.NewErrAsn1Syntax("invalid UTF-8 string")
		}
		return asn1.UTF8String(value), nil
	case Tag(asn1.TagBMPString):
		// BMPString uses the defunct UCS-2 16-bit character encoding, which
		// covers the Basic Multilingual Plane (BMP). UTF-16 was an extension of
		// UCS-2, containing all of the same code points, but also including
		// multi-code point characters (by using surrogate code points). We can
		// treat a UCS-2 encoded string as a UTF-16 encoded string, as long as
		// we reject out the UTF-16 specific code points. This matches the
		// BoringSSL behavior.

		if len(value)%2 != 0 {
			return "", pkerr.NewErrAsn1Syntax("invalid BMPString")
		}

		// Strip terminator if present.
		if l := len(value); l >= 2 && value[l-1] == 0 && value[l-2] == 0 {
			value = value[:l-2]
		}

		s := make([]uint16, 0, len(value)/2)
		for len(value) > 0 {
			point := uint16(value[0])<<8 + uint16(value[1])
			// Reject UTF-16 code points that are permanently reserved
			// noncharacters (0xfffe, 0xffff, and 0xfdd0-0xfdef) and surrogates
			// (0xd800-0xdfff).
			if point == 0xfffe || point == 0xffff ||
				(point >= 0xfdd0 && point <= 0xfdef) ||
				(point >= 0xd800 && point <= 0xdfff) {
				return "", pkerr.NewErrAsn1Syntax("invalid BMPString")
			}
			s = append(s, point)
			value = value[2:]
		}

		return asn1.BMPString(utf16.Decode(s)), nil
	case IA5String:
		s := string(value)
		if asn1.IsIA5String(s) != nil {
			return "", pkerr.NewErrAsn1Syntax("invalid IA5String")
		}
		return asn1.IA5String(value), nil
	case Tag(asn1.TagNumericString):
		for _, b := range value {
			if !('0' <= b && b <= '9' || b == ' ') {
				return "", pkerr.NewErrAsn1Syntax("invalid NumericString")
			}
		}
		return asn1.NUMERICString(value), nil
	}
	return "", pkerr.NewErrUnsupportedStringType(tag)
}

// parseName parses a DER encoded Name as defined in RFC 5280. We may
// want to export this function in the future for use in crypto/tls.
func (raw String) ParseName() (*pkix.RDNSequence, pkerr.Kerror) {
	if !raw.ReadASN1(&raw, SEQUENCE) {
		return nil, pkerr.NewErrInvalidRDNSequence()
	}

	var rdnSeq pkix.RDNSequence
	for !raw.Empty() {
		var rdnSet pkix.RelativeDistinguishedNameSET
		var set String
		if !raw.ReadASN1(&set, SET) {
			return nil, pkerr.NewErrInvalidRDNSequence()
		}
		for !set.Empty() {
			var atav String
			if !set.ReadASN1(&atav, SEQUENCE) {
				return nil, pkerr.NewErrInvalidRDNSequence("")
			}
			var attr pkix.AttributeTypeAndValue
			if !atav.ReadASN1ObjectIdentifier(&attr.Type) {
				return nil, pkerr.NewErrInvalidRDNSequence(" type")
			}
			var rawValue String
			var valueTag Tag
			if !atav.ReadAnyASN1(&rawValue, &valueTag) {
				return nil, pkerr.NewErrInvalidRDNSequence(" value")
			}
			var err pkerr.Kerror
			attr.Value, err = valueTag.ParseASN1String(rawValue)
			if err != nil {
				return nil, pkerr.NewErrInvalidRDNSequence(" value: " + err.Error())
			}
			rdnSet = append(rdnSet, attr)
		}

		rdnSeq = append(rdnSeq, rdnSet)
	}

	return &rdnSeq, nil
}

func (der String) ParseExtension() (pkix.Extension, pkerr.Kerror) {
	var ext pkix.Extension
	if !der.ReadASN1ObjectIdentifier(&ext.Id) {
		return ext, pkerr.NewErrInvalidASN1OID()
	}
	if der.PeekASN1Tag(BOOLEAN) {
		if !der.ReadASN1Boolean(&ext.Critical) {
			return ext, pkerr.NewErrInvalidASN1Critical()
		}
	}
	var val String
	if !der.ReadASN1(&val, OCTET_STRING) {
		return ext, pkerr.NewErrInvalidASN1Value()
	}
	ext.Value = val
	return ext, nil
}

func (der *String) ParseTime() (time.Time, pkerr.Kerror) {
	var t time.Time
	switch {
	case der.PeekASN1Tag(UTCTime):
		if !der.ReadASN1UTCTime(&t) {
			return t, pkerr.NewErrMalformedUTCTime()
		}
	case der.PeekASN1Tag(GeneralizedTime):
		if !der.ReadASN1GeneralizedTime(&t) {
			return t, pkerr.NewErrMalformedGeneralizedTime()
		}
	default:
		return t, pkerr.NewErrMalformedTime()
	}
	return t, nil
}

func (der String) ParseValidity() (time.Time, time.Time, pkerr.Kerror) {
	notBefore, err := der.ParseTime()
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	notAfter, err := der.ParseTime()
	if err != nil {
		return time.Time{}, time.Time{}, err
	}

	return notBefore, notAfter, nil
}
