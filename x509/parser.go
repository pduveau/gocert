// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"bytes"
	"math"
	"math/big"
	"net"
	"net/url"
	"strings"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/internal/keys"
	"github.com/pduveau/gocert/internal/pkixstring"
	"github.com/pduveau/gocert/pkerr"
	"github.com/pduveau/gocert/pkix"
)

func parseKeyUsageExtension(der pkixstring.String) (KeyUsage, pkerr.Kerror) {
	var usageBits asn1.BitString
	if !der.ReadASN1BitString(&usageBits) {
		return 0, pkerr.NewErrInvalidKeyUsage()
	}

	var usage int
	for i := 0; i < 9; i++ {
		if usageBits.At(i) != 0 {
			usage |= 1 << uint(i)
		}
	}
	return KeyUsage(usage), nil
}

func parseBasicConstraintsExtension(der pkixstring.String) (bool, int, pkerr.Kerror) {
	var isCA bool
	if !der.ReadASN1(&der, pkixstring.SEQUENCE) {
		return false, 0, pkerr.NewErrInvalidBasicConstraints()
	}
	if der.PeekASN1Tag(pkixstring.BOOLEAN) {
		if !der.ReadASN1Boolean(&isCA) {
			return false, 0, pkerr.NewErrInvalidBasicConstraints()
		}
	}

	maxPathLen := -1
	if der.PeekASN1Tag(pkixstring.INTEGER) {
		var mpl uint
		if !der.ReadASN1Integer(&mpl) || mpl > math.MaxInt {
			return false, 0, pkerr.NewErrInvalidBasicConstraints()
		}
		maxPathLen = int(mpl)
	}

	return isCA, maxPathLen, nil
}

// pareReadRegisterID decodes an ASN.1 OBJECT IDENTIFIER into out and
// advances. It reports whether the read was successful.
func pareReadRegisterID(s []byte, out *pkix.RegisterID) bool {
	oid, err := asn1.ParseObjectIdentifier(s)
	if err != nil {
		return false
	}
	*out = pkix.RegisterID(oid)
	return true
}

func forEachSAN(der pkixstring.String, callback func(tag int, data []byte) pkerr.Kerror) pkerr.Kerror {
	if !der.ReadASN1(&der, pkixstring.SEQUENCE) {
		return pkerr.NewErrInvalidSAN()
	}
	for !der.Empty() {
		var san pkixstring.String
		var tag pkixstring.Tag
		if !der.ReadAnyASN1(&san, &tag) {
			return pkerr.NewErrInvalidSAN()
		}
		if err := callback(int(tag&0x1F), san); err != nil {
			return err
		}
	}

	return nil
}

func ParseSANExtension(der pkixstring.String) (*SubjectAlternativeName, pkerr.Kerror) {

	var san SubjectAlternativeName
	var out *SubjectAlternativeName

	err := forEachSAN(der, func(tag int, data []byte) pkerr.Kerror {
		switch tag {
		case nameTypeOther:
			var otherName pkix.OtherName
			var rest []byte
			rest, err := asn1.Unmarshal(data, &otherName.Type)
			if err != nil && len(rest) == 0 {
				return pkerr.NewErrMalformedSANOtherName(err)
			}
			rest, err = asn1.Unmarshal(rest, &otherName.Value)
			if err != nil && len(rest) > 0 {
				return pkerr.NewErrMalformedSANOtherName(nil)
			}
			san.OtherNames = append(san.OtherNames, otherName)
			out = &san
		case nameTypeEmail:
			email := string(data)
			if err := asn1.IsIA5String(email); err != nil {
				return pkerr.NewErrMalformedRfc822Name()
			}
			san.EmailAddresses = append(san.EmailAddresses, email)
			out = &san
		case nameTypeDNS:
			name := string(data)
			if err := asn1.IsIA5String(name); err != nil {
				return pkerr.NewErrMalformedSANDnsName()
			}
			san.DNSNames = append(san.DNSNames, string(name))
			out = &san
		case nameTypeDirectory:
			var rawName *pkix.RDNSequence
			var name pkix.Name
			rawName, err := pkixstring.String(data).ParseName()
			if err != nil {
				return pkerr.NewErrMalformedSANDirectoryName()
			}
			name.FillFromRDNSequence(rawName)
			san.DirectoryNames = append(san.DirectoryNames, name)
			out = &san
		case nameTypeURI:
			uriStr := string(data)
			if err := asn1.IsIA5String(uriStr); err != nil {
				return pkerr.NewErrMalformedSANURI()
			}
			uri, err := url.Parse(uriStr)
			if err != nil {
				return pkerr.NewErrParsingURI(uriStr, err.Error())
			}
			if len(uri.Host) > 0 && !domainNameValid(uri.Host, false) {
				return pkerr.NewErrParsingURI(uriStr, "invalid domain")
			}
			san.URIs = append(san.URIs, uri)
			out = &san
		case nameTypeIP:
			switch len(data) {
			case net.IPv4len, net.IPv6len:
				san.IPAddresses = append(san.IPAddresses, data)
				out = &san
			default:
				return pkerr.NewErrParsingIpAddress(len(data))
			}
		case nameTypeRegisterID:
			var oid pkix.RegisterID
			if !pareReadRegisterID(data, &oid) {
				return pkerr.NewErrMalformedRegisterID()
			}
			san.RegisterIDs = append(san.RegisterIDs, oid)
			out = &san
		}

		return nil
	})

	return out, err
}

func parseExtKeyUsageExtension(der pkixstring.String) ([]ExtKeyUsage, []asn1.ObjectIdentifier, pkerr.Kerror) {
	var extKeyUsages []ExtKeyUsage
	var unknownUsages []asn1.ObjectIdentifier
	if !der.ReadASN1(&der, pkixstring.SEQUENCE) {
		return nil, nil, pkerr.NewErrInvalidEKU()
	}
	for !der.Empty() {
		var eku asn1.ObjectIdentifier
		if !der.ReadASN1ObjectIdentifier(&eku) {
			return nil, nil, pkerr.NewErrInvalidEKU()
		}
		if extKeyUsage, ok := extKeyUsageFromOID(eku); ok {
			extKeyUsages = append(extKeyUsages, extKeyUsage)
		} else {
			unknownUsages = append(unknownUsages, eku)
		}
	}
	return extKeyUsages, unknownUsages, nil
}

func parseCertificatePoliciesExtension(der pkixstring.String) ([]OID, pkerr.Kerror) {
	var oids []OID
	seenOIDs := map[string]bool{}
	if !der.ReadASN1(&der, pkixstring.SEQUENCE) {
		return nil, pkerr.NewErrInvalidCertificatePolices()
	}
	for !der.Empty() {
		var cp pkixstring.String
		var OIDBytes pkixstring.String
		if !der.ReadASN1(&cp, pkixstring.SEQUENCE) || !cp.ReadASN1(&OIDBytes, pkixstring.OBJECT_IDENTIFIER) {
			return nil, pkerr.NewErrInvalidCertificatePolices()
		}
		if seenOIDs[string(OIDBytes)] {
			return nil, pkerr.NewErrInvalidCertificatePolices()
		}
		seenOIDs[string(OIDBytes)] = true
		oid, ok := newOIDFromDER(OIDBytes)
		if !ok {
			return nil, pkerr.NewErrInvalidCertificatePolices()
		}
		oids = append(oids, oid)
	}
	return oids, nil
}

// isValidIPMask reports whether mask consists of zero or more 1 bits, followed by zero bits.
func isValidIPMask(mask []byte) bool {
	seenZero := false

	for _, b := range mask {
		if seenZero {
			if b != 0 {
				return false
			}

			continue
		}

		switch b {
		case 0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe:
			seenZero = true
		case 0xff:
		default:
			return false
		}
	}

	return true
}

func parseNameConstraintsExtension(out *Certificate, e pkix.Extension) (unhandled bool, err pkerr.Kerror) {
	// RFC 5280, 4.2.1.10

	// NameConstraints ::= SEQUENCE {
	//      permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
	//      excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
	//
	// GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
	//
	// GeneralSubtree ::= SEQUENCE {
	//      base                    GeneralName,
	//      minimum         [0]     BaseDistance DEFAULT 0,
	//      maximum         [1]     BaseDistance OPTIONAL }
	//
	// BaseDistance ::= INTEGER (0..MAX)

	outer := pkixstring.String(e.Value)
	var toplevel, permitted, excluded pkixstring.String
	var havePermitted, haveExcluded bool
	if !outer.ReadASN1(&toplevel, pkixstring.SEQUENCE) ||
		!outer.Empty() ||
		!toplevel.ReadOptionalASN1(&permitted, &havePermitted, pkixstring.Tag(0).ContextSpecific().Constructed()) ||
		!toplevel.ReadOptionalASN1(&excluded, &haveExcluded, pkixstring.Tag(1).ContextSpecific().Constructed()) ||
		!toplevel.Empty() {
		return false, pkerr.NewErrInvalidNameConstraintsExtension()
	}

	if !havePermitted && !haveExcluded || len(permitted) == 0 && len(excluded) == 0 {
		// From RFC 5280, Section 4.2.1.10:
		//   “either the permittedSubtrees field
		//   or the excludedSubtrees MUST be
		//   present”
		return false, pkerr.NewErrEmptyNameConstraintsExtension()
	}

	getValues := func(subtrees pkixstring.String) (dnsNames []string, ips []*net.IPNet, emails, uriDomains []string, err pkerr.Kerror) {
		for !subtrees.Empty() {
			var seq, value pkixstring.String
			var tag pkixstring.Tag
			if !subtrees.ReadASN1(&seq, pkixstring.SEQUENCE) ||
				!seq.ReadAnyASN1(&value, &tag) {
				return nil, nil, nil, nil, pkerr.NewErrInvalidNameConstraintsExtension()
			}

			var (
				dnsTag   = pkixstring.Tag(2).ContextSpecific()
				emailTag = pkixstring.Tag(1).ContextSpecific()
				ipTag    = pkixstring.Tag(7).ContextSpecific()
				uriTag   = pkixstring.Tag(6).ContextSpecific()
			)

			switch tag {
			case dnsTag:
				domain := string(value)
				if err := asn1.IsIA5String(domain); err != nil {
					return nil, nil, nil, nil, pkerr.NewErrInvalidConstraintValue(err)
				}

				if !domainNameValid(domain, true) {
					return nil, nil, nil, nil, pkerr.NewErrInvalidConstraintValue(domain)
				}
				dnsNames = append(dnsNames, domain)

			case ipTag:
				l := len(value)
				var ip, mask []byte

				switch l {
				case 8:
					ip = value[:4]
					mask = value[4:]

				case 32:
					ip = value[:16]
					mask = value[16:]

				default:
					return nil, nil, nil, nil, pkerr.NewErrIPContraintValueLen(l)
				}

				if !isValidIPMask(mask) {
					return nil, nil, nil, nil, pkerr.NewErrIPContraintInvalidMask(mask)
				}

				ips = append(ips, &net.IPNet{IP: net.IP(ip), Mask: net.IPMask(mask)})

			case emailTag:
				constraint := string(value)
				if err := asn1.IsIA5String(constraint); err != nil {
					return nil, nil, nil, nil, pkerr.NewErrParsingRfc822NameConstraint(err)
				}

				// If the constraint contains an @ then
				// it specifies an exact mailbox name.
				if strings.Contains(constraint, "@") {
					if _, ok := parseRFC2821Mailbox(constraint); !ok {
						return nil, nil, nil, nil, pkerr.NewErrParsingRfc822NameConstraint(constraint)
					}
				} else {
					if !domainNameValid(constraint, true) {
						return nil, nil, nil, nil, pkerr.NewErrParsingRfc822NameConstraint(constraint)
					}
				}
				emails = append(emails, constraint)

			case uriTag:
				domain := string(value)
				if err := asn1.IsIA5String(domain); err != nil {
					return nil, nil, nil, nil, pkerr.NewErrParsingURIConstraint(err.Error())
				}

				if net.ParseIP(domain) != nil {
					return nil, nil, nil, nil, pkerr.NewErrParsingURIConstraint(domain)
				}

				if !domainNameValid(domain, true) {
					return nil, nil, nil, nil, pkerr.NewErrParsingURIConstraint(domain)
				}
				uriDomains = append(uriDomains, domain)

			default:
				unhandled = true
			}
		}

		return dnsNames, ips, emails, uriDomains, nil
	}

	if out.PermittedDNSDomains, out.PermittedIPRanges, out.PermittedEmailAddresses, out.PermittedURIDomains, err = getValues(permitted); err != nil {
		return false, err
	}
	if out.ExcludedDNSDomains, out.ExcludedIPRanges, out.ExcludedEmailAddresses, out.ExcludedURIDomains, err = getValues(excluded); err != nil {
		return false, err
	}
	out.PermittedDNSDomainsCritical = e.Critical

	return unhandled, nil
}

func processExtensions(out *Certificate) pkerr.Kerror {
	var err pkerr.Kerror
	for _, e := range out.Extensions {
		unhandled := false

		if len(e.Id) == 4 && e.Id[0] == 2 && e.Id[1] == 5 && e.Id[2] == 29 {
			switch e.Id[3] {
			case 15:
				out.KeyUsage, err = parseKeyUsageExtension(e.Value)
				if err != nil {
					return err
				}
			case 19:
				out.IsCA, out.MaxPathLen, err = parseBasicConstraintsExtension(e.Value)
				if err != nil {
					return err
				}
				out.BasicConstraintsValid = true
				out.MaxPathLenZero = out.MaxPathLen == 0
			case 17:
				out.San, err = ParseSANExtension(e.Value)
				if err != nil {
					return err
				}

				if out.San == nil {
					// If we didn't parse anything then we do the critical check, below.
					unhandled = true
				}

			case 30:
				unhandled, err = parseNameConstraintsExtension(out, e)
				if err != nil {
					return err
				}

			case 31:
				// RFC 5280, 4.2.1.13

				// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
				//
				// DistributionPoint ::= SEQUENCE {
				//     distributionPoint       [0]     DistributionPointName OPTIONAL,
				//     reasons                 [1]     ReasonFlags OPTIONAL,
				//     cRLIssuer               [2]     GeneralNames OPTIONAL }
				//
				// DistributionPointName ::= CHOICE {
				//     fullName                [0]     GeneralNames,
				//     nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
				val := pkixstring.String(e.Value)
				if !val.ReadASN1(&val, pkixstring.SEQUENCE) {
					return pkerr.NewErrInvalidCRLDP()
				}
				for !val.Empty() {
					var dpDER pkixstring.String
					if !val.ReadASN1(&dpDER, pkixstring.SEQUENCE) {
						return pkerr.NewErrInvalidCRLDP()
					}
					var dpNameDER pkixstring.String
					var dpNamePresent bool
					if !dpDER.ReadOptionalASN1(&dpNameDER, &dpNamePresent, pkixstring.Tag(0).Constructed().ContextSpecific()) {
						return pkerr.NewErrInvalidCRLDP()
					}
					if !dpNamePresent {
						continue
					}
					if !dpNameDER.ReadASN1(&dpNameDER, pkixstring.Tag(0).Constructed().ContextSpecific()) {
						return pkerr.NewErrInvalidCRLDP()
					}
					for !dpNameDER.Empty() {
						if !dpNameDER.PeekASN1Tag(pkixstring.Tag(6).ContextSpecific()) {
							break
						}
						var uri pkixstring.String
						if !dpNameDER.ReadASN1(&uri, pkixstring.Tag(6).ContextSpecific()) {
							return pkerr.NewErrInvalidCRLDP()
						}
						out.CRLDistributionPoints = append(out.CRLDistributionPoints, string(uri))
					}
				}

			case 35:
				out.AuthorityKeyId, err = pkixstring.ParseAuthorityKeyIdentifier(e)
				if err != nil {
					return err
				}
			case 36:
				val := pkixstring.String(e.Value)
				if !val.ReadASN1(&val, pkixstring.SEQUENCE) {
					return pkerr.NewErrInvalidPolicyConstraintsExtension()
				}
				if val.PeekASN1Tag(pkixstring.Tag(0).ContextSpecific()) {
					var v int64
					if !val.ReadASN1Int64WithTag(&v, pkixstring.Tag(0).ContextSpecific()) {
						return pkerr.NewErrInvalidPolicyConstraintsExtension()
					}
					out.RequireExplicitPolicy = int(v)
					// Check for overflow.
					if int64(out.RequireExplicitPolicy) != v {
						return pkerr.NewErrPolicyConstraintsRequireExplicitPolicyField()
					}
					out.RequireExplicitPolicyZero = out.RequireExplicitPolicy == 0
				}
				if val.PeekASN1Tag(pkixstring.Tag(1).ContextSpecific()) {
					var v int64
					if !val.ReadASN1Int64WithTag(&v, pkixstring.Tag(1).ContextSpecific()) {
						return pkerr.NewErrInvalidPolicyConstraintsExtension()
					}
					out.InhibitPolicyMapping = int(v)
					// Check for overflow.
					if int64(out.InhibitPolicyMapping) != v {
						return pkerr.NewErrPolicyConstraintsInhibitPolicyMappingField()
					}
					out.InhibitPolicyMappingZero = out.InhibitPolicyMapping == 0
				}
			case 37:
				out.ExtKeyUsage, out.UnknownExtKeyUsage, err = parseExtKeyUsageExtension(e.Value)
				if err != nil {
					return err
				}
			case 14: // RFC 5280, 4.2.1.2
				if e.Critical {
					// Conforming CAs MUST mark this extension as non-critical
					return pkerr.NewErrSKIIncorrectlyMarkedCritical()
				}
				val := pkixstring.String(e.Value)
				var skid pkixstring.String
				if !val.ReadASN1(&skid, pkixstring.OCTET_STRING) {
					return pkerr.NewErrInvalidSKI()
				}
				out.SubjectKeyId = skid
			case 32:
				out.Policies, err = parseCertificatePoliciesExtension(e.Value)
				if err != nil {
					return err
				}
			case 33:
				val := pkixstring.String(e.Value)
				if !val.ReadASN1(&val, pkixstring.SEQUENCE) {
					return pkerr.NewErrInvalidPolicyMappingsExtension()
				}
				for !val.Empty() {
					var s pkixstring.String
					var issuer, subject pkixstring.String
					if !val.ReadASN1(&s, pkixstring.SEQUENCE) ||
						!s.ReadASN1(&issuer, pkixstring.OBJECT_IDENTIFIER) ||
						!s.ReadASN1(&subject, pkixstring.OBJECT_IDENTIFIER) {
						return pkerr.NewErrInvalidPolicyMappingsExtension()
					}
					out.PolicyMappings = append(out.PolicyMappings, PolicyMapping{OID{issuer}, OID{subject}})
				}
			case 54:
				val := pkixstring.String(e.Value)
				if !val.ReadASN1Integer(&out.InhibitAnyPolicy) {
					return pkerr.NewErrInvalidInhibitAnyPolicyExtension()
				}
				out.InhibitAnyPolicyZero = out.InhibitAnyPolicy == 0
			default:
				// Unknown extensions are recorded if critical.
				unhandled = true
			}
		} else if e.Id.Equal(oidExtensionAuthorityInfoAccess) {
			// RFC 5280 4.2.2.1: Authority Information Access
			if e.Critical {
				// Conforming CAs MUST mark this extension as non-critical
				return pkerr.NewErrAuthorityInfoAccessMarkedCritical()
			}
			val := pkixstring.String(e.Value)
			if !val.ReadASN1(&val, pkixstring.SEQUENCE) {
				return pkerr.NewErrInvalidAuthorityInfoAccess()
			}
			for !val.Empty() {
				var aiaDER pkixstring.String
				if !val.ReadASN1(&aiaDER, pkixstring.SEQUENCE) {
					return pkerr.NewErrInvalidAuthorityInfoAccess()
				}
				var method asn1.ObjectIdentifier
				if !aiaDER.ReadASN1ObjectIdentifier(&method) {
					return pkerr.NewErrInvalidAuthorityInfoAccess()
				}
				if !aiaDER.PeekASN1Tag(pkixstring.Tag(6).ContextSpecific()) {
					continue
				}
				if !aiaDER.ReadASN1(&aiaDER, pkixstring.Tag(6).ContextSpecific()) {
					return pkerr.NewErrInvalidAuthorityInfoAccess()
				}
				switch {
				case method.Equal(oidAuthorityInfoAccessOcsp):
					out.OCSPServer = append(out.OCSPServer, string(aiaDER))
				case method.Equal(oidAuthorityInfoAccessIssuers):
					out.IssuingCertificateURL = append(out.IssuingCertificateURL, string(aiaDER))
				}
			}
		} else {
			// Unknown extensions are recorded if critical.
			unhandled = true
		}

		if e.Critical && unhandled {
			out.UnhandledCriticalExtensions = append(out.UnhandledCriticalExtensions, e.Id)
		}
	}

	return nil
}

func parseCertificate(der []byte) (*Certificate, pkerr.Kerror) {
	cert := &Certificate{}

	input := pkixstring.String(der)
	// we read the SEQUENCE including length and tag bytes so that
	// we can populate Certificate.Raw, before unwrapping the
	// SEQUENCE so it can be operated on
	if !input.ReadASN1Element(&input, pkixstring.SEQUENCE) {
		return nil, pkerr.NewErrMalformedCertificate()
	}
	cert.Raw = input
	if !input.ReadASN1(&input, pkixstring.SEQUENCE) {
		return nil, pkerr.NewErrMalformedCertificate()
	}

	var tbs pkixstring.String
	// do the same trick again as above to extract the raw
	// bytes for Certificate.RawTBSCertificate
	if !input.ReadASN1Element(&tbs, pkixstring.SEQUENCE) {
		return nil, pkerr.NewErrMalformedTbsCertificate()
	}
	cert.RawTBSCertificate = tbs
	if !tbs.ReadASN1(&tbs, pkixstring.SEQUENCE) {
		return nil, pkerr.NewErrMalformedTbsCertificate()
	}

	if !tbs.ReadOptionalASN1Integer(&cert.Version, pkixstring.Tag(0).Constructed().ContextSpecific(), 0) {
		return nil, pkerr.NewErrMalformedVersion()
	}
	if cert.Version < 0 {
		return nil, pkerr.NewErrMalformedVersion()
	}
	// for backwards compat reasons Version is one-indexed,
	// rather than zero-indexed as defined in 5280
	cert.Version++
	if cert.Version > 3 {
		return nil, pkerr.NewErrMalformedVersion()
	}

	serial := new(big.Int)
	if !tbs.ReadASN1Integer(serial) {
		return nil, pkerr.NewErrMalformedSerialNumber()
	}
	if serial.Sign() == -1 {
		return nil, pkerr.NewErrMalformedSerialNumber()
	}
	cert.SerialNumber = serial

	var sigAISeq pkixstring.String
	if !tbs.ReadASN1(&sigAISeq, pkixstring.SEQUENCE) {
		return nil, pkerr.NewErrMalformedSignatureAlgorithmIdentifier()
	}
	// Before parsing the inner algorithm identifier, extract
	// the outer algorithm identifier and make sure that they
	// match.
	var outerSigAISeq pkixstring.String
	if !input.ReadASN1(&outerSigAISeq, pkixstring.SEQUENCE) {
		return nil, pkerr.NewErrMalformedSignatureAlgorithmIdentifier()
	}
	if !bytes.Equal(outerSigAISeq, sigAISeq) {
		return nil, pkerr.NewErrInnerOuterSignatureIdentifiersDontMatch()
	}
	sigAI, err := sigAISeq.ParseAI()
	if err != nil {
		return nil, err
	}
	cert.SignatureAlgorithm = sigAI.GetSignatureAlgorithm()

	var issuerSeq pkixstring.String
	if !tbs.ReadASN1Element(&issuerSeq, pkixstring.SEQUENCE) {
		return nil, pkerr.NewErrMalformedIssuer()
	}
	cert.RawIssuer = issuerSeq
	issuerRDNs, err := issuerSeq.ParseName()
	if err != nil {
		return nil, err
	}
	cert.Issuer.FillFromRDNSequence(issuerRDNs)

	var validity pkixstring.String
	if !tbs.ReadASN1(&validity, pkixstring.SEQUENCE) {
		return nil, pkerr.NewErrMalformedValidity()
	}
	cert.NotBefore, cert.NotAfter, err = validity.ParseValidity()
	if err != nil {
		return nil, err
	}

	var subjectSeq pkixstring.String
	if !tbs.ReadASN1Element(&subjectSeq, pkixstring.SEQUENCE) {
		return nil, pkerr.NewErrMalformedIssuer()
	}
	cert.RawSubject = subjectSeq
	subjectRDNs, err := subjectSeq.ParseName()
	if err != nil {
		return nil, err
	}
	cert.Subject.FillFromRDNSequence(subjectRDNs)

	var spki pkixstring.String
	if !tbs.ReadASN1Element(&spki, pkixstring.SEQUENCE) {
		return nil, pkerr.NewErrMalformedSPKI()
	}
	cert.RawSubjectPublicKeyInfo = spki
	if !spki.ReadASN1(&spki, pkixstring.SEQUENCE) {
		return nil, pkerr.NewErrMalformedSPKI()
	}
	var pkAISeq pkixstring.String
	if !spki.ReadASN1(&pkAISeq, pkixstring.SEQUENCE) {
		return nil, pkerr.NewErrMalformedpublicKeyAlgorithmIdentifier()
	}
	pkAI, err := pkAISeq.ParseAI()
	if err != nil {
		return nil, err
	}
	cert.PublicKeyAlgorithm = pkix.GetPublicKeyAlgorithmFromOID(pkAI.Algorithm)
	var spk asn1.BitString
	if !spki.ReadASN1BitString(&spk) {
		return nil, pkerr.NewErrMalformedSubjectPublicKey()
	}
	if cert.PublicKeyAlgorithm != pkix.UnknownPublicKeyAlgorithm {
		cert.PublicKey, err = (&keys.PublicKeyInfo{
			Algorithm: pkAI,
			PublicKey: spk,
		}).ParsePublicKey()
		if err != nil {
			return nil, err
		}
	}

	if cert.Version > 1 {
		if !tbs.SkipOptionalASN1(pkixstring.Tag(1).ContextSpecific()) {
			return nil, pkerr.NewErrMalformedIssuerUniqueID()
		}
		if !tbs.SkipOptionalASN1(pkixstring.Tag(2).ContextSpecific()) {
			return nil, pkerr.NewErrMalformedSubjectUniqueID()
		}
		if cert.Version == 3 {
			var extensions pkixstring.String
			var present bool
			if !tbs.ReadOptionalASN1(&extensions, &present, pkixstring.Tag(3).Constructed().ContextSpecific()) {
				return nil, pkerr.NewErrMalformedExtensions()
			}
			if present {
				seenExts := make(map[string]bool)
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
					oidStr := ext.Id.String()
					if seenExts[oidStr] {
						return nil, pkerr.NewErrCertificateContainsDuplicateExtension(oidStr)
					}
					seenExts[oidStr] = true
					cert.Extensions = append(cert.Extensions, ext)
				}
				err = processExtensions(cert)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	var signature asn1.BitString
	if !input.ReadASN1BitString(&signature) {
		return nil, pkerr.NewErrMalformedSignature()
	}
	cert.Signature = signature.RightAlign()

	return cert, nil
}

// ParseCertificate parses a single certificate from the given ASN.1 DER data.
func ParseCertificate(der []byte) (*Certificate, pkerr.Kerror) {
	cert, err := parseCertificate(der)
	if err != nil {
		return nil, err
	}
	if len(der) != len(cert.Raw) {
		return nil, pkerr.NewErrASN1TrailingData("certificate")
	}
	return cert, nil
}

// ParseCertificates parses one or more certificates from the given ASN.1 DER
// data. The certificates must be concatenated with no intermediate padding.
func ParseCertificates(der []byte) ([]*Certificate, pkerr.Kerror) {
	var certs []*Certificate
	for len(der) > 0 {
		cert, err := parseCertificate(der)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
		der = der[len(cert.Raw):]
	}
	return certs, nil
}

// domainNameValid is an alloc-less version of the checks that
// domainToReverseLabels does.
func domainNameValid(s string, constraint bool) bool {
	// TODO(#75835): This function omits a number of checks which we
	// really should be doing to enforce that domain names are valid names per
	// RFC 1034. We previously enabled these checks, but this broke a
	// significant number of certificates we previously considered valid, and we
	// happily create via CreateCertificate (et al). We should enable these
	// checks, but will need to gate them behind a GODEBUG.
	//
	// I have left the checks we previously enabled, noted with "TODO(#75835)" so
	// that we can easily re-enable them once we unbreak everyone.

	// TODO(#75835): this should only be true for constraints.
	if len(s) == 0 {
		return true
	}

	// Do not allow trailing period (FQDN format is not allowed in SANs or
	// constraints).
	if s[len(s)-1] == '.' {
		return false
	}

	// TODO(#75835): domains must have at least one label, cannot have
	// a leading empty label, and cannot be longer than 253 characters.
	// if len(s) == 0 || (!constraint && s[0] == '.') || len(s) > 253 {
	// 	return false
	// }

	lastDot := -1
	if constraint && s[0] == '.' {
		s = s[1:]
	}

	for i := 0; i <= len(s); i++ {
		if i < len(s) && (s[i] < 33 || s[i] > 126) {
			// Invalid character.
			return false
		}
		if i == len(s) || s[i] == '.' {
			labelLen := i
			if lastDot >= 0 {
				labelLen -= lastDot + 1
			}
			if labelLen == 0 {
				return false
			}
			// TODO(#75835): labels cannot be longer than 63 characters.
			// if labelLen > 63 {
			// 	return false
			// }
			lastDot = i
		}
	}

	return true
}
