package pkerr

type ErrAKICritical struct{ BaseError }

func NewErrAKICritical() Kerror {
	return &ErrAKICritical{BaseError: newBaseError(NumErrAKICritical, "authority key identifier incorrectly marked critical")}
}

type ErrInvalidAKI struct{ BaseError }

func NewErrInvalidAKI() Kerror {
	return &ErrInvalidAKI{BaseError: newBaseError(NumErrInvalidAKI, "invalid authority key identifier")}
}

type ErrInvalidASN1OID struct{ BaseError }

func NewErrInvalidASN1OID() Kerror {
	return &ErrInvalidASN1OID{BaseError: newBaseError(NumErrInvalidASN1OID, "invalid/malformed OID")}
}

type ErrInvalidASN1Params struct{ BaseError }

func NewErrInvalidASN1Params() Kerror {
	return &ErrInvalidASN1Params{BaseError: newBaseError(NumErrInvalidASN1Params, "invalid/malformed parameters")}
}

type ErrInvalidASN1Critical struct{ BaseError }

func NewErrInvalidASN1Critical() Kerror {
	return &ErrInvalidASN1Critical{BaseError: newBaseError(NumErrInvalidASN1Critical, "invalid/malformed critical field")}
}

type ErrInvalidASN1Value struct{ BaseError }

func NewErrInvalidASN1Value() Kerror {
	return &ErrInvalidASN1Value{BaseError: newBaseError(NumErrInvalidASN1Value, "invalid/malformed value field")}
}

type ErrConstraintViolation struct{ BaseError }

func NewErrConstraintViolation() Kerror {
	return &ErrConstraintViolation{BaseError: newBaseError(NumErrConstraintViolation, "invalid signature: parent certificate cannot sign this kind of certificate")}
}

type ErrInvalidIssuer struct{ BaseError }

func NewErrInvalidIssuer() Kerror {
	return &ErrInvalidIssuer{BaseError: newBaseError(NumErrInvalidIssuer, "malformed issuer")}
}

type ErrMalformedSerialNumber struct{ BaseError }

func NewErrMalformedSerialNumber() Kerror {
	return &ErrMalformedSerialNumber{BaseError: newBaseError(NumErrMalformedSerialNumber, "malformed serial number")}
}

type ErrMalformedExtensions struct{ BaseError }

func NewErrMalformedExtensions() Kerror {
	return &ErrMalformedExtensions{BaseError: newBaseError(NumErrMalformedExtensions, "malformed extensions")}
}

type ErrUnhandledCriticalExtension struct{ BaseError }

func NewErrUnhandledCriticalExtension() Kerror {
	return &ErrUnhandledCriticalExtension{BaseError: newBaseError(NumErrUnhandledCriticalExtension, "unhandled critical extension")}
}

type ErrASN1TrailingData struct{ BaseError }

func NewErrASN1TrailingData(where string) Kerror {
	return &ErrASN1TrailingData{BaseError: newBaseErrorData(NumErrASN1TrailingData, "trailing data after ASN.1 of %s", where)}
}

type ErrUnknownEKU struct{ BaseError }

func NewErrUnknownEKU() Kerror {
	return &ErrUnknownEKU{BaseError: newBaseError(NumErrUnknownEKU, "unknown extended key usage")}
}

type ErrPublicKeyTypeNoEqual struct{ BaseError }

func NewErrPublicKeyTypeNoEqual() Kerror {
	return &ErrPublicKeyTypeNoEqual{BaseError: newBaseError(NumErrPublicKeyTypeNoEqual, "supported public key does not implement Equal")}
}

type ErrPrivateKeyDoesNotMatchParentPublicKey struct{ BaseError }

func NewErrPrivateKeyDoesNotMatchParentPublicKey() Kerror {
	return &ErrPrivateKeyDoesNotMatchParentPublicKey{BaseError: newBaseError(NumErrPrivateKeyDoesNotMatchParentPublicKey, "provided PrivateKey doesn't match parent's PublicKey")}
}

type ErrSerialNumberNegative struct{ BaseError }

func NewErrSerialNumberNegative() Kerror {
	return &ErrSerialNumberNegative{BaseError: newBaseError(NumErrSerialNumberNegative, "serial number must be positive")}
}

type ErrMaxPathLenNegative struct{ BaseError }

func NewErrMaxPathLenNegative() Kerror {
	return &ErrMaxPathLenNegative{BaseError: newBaseError(NumErrMaxPathLenNegative, "invalid MaxPathLen, must be greater or equal to -1")}
}

type ErrMaxPathLenOnlyCA struct{ BaseError }

func NewErrMaxPathLenOnlyCA() Kerror {
	return &ErrMaxPathLenOnlyCA{BaseError: newBaseError(NumErrMaxPathLenOnlyCA, "only CAs are allowed to specify MaxPathLen")}
}

type ErrInvalidKeyUsage struct{ BaseError }

func NewErrInvalidKeyUsage() Kerror {
	return &ErrInvalidKeyUsage{BaseError: newBaseError(NumErrInvalidKeyUsage, "invalid key usage")}
}

type ErrInvalidBasicConstraints struct{ BaseError }

func NewErrInvalidBasicConstraints() Kerror {
	return &ErrInvalidBasicConstraints{BaseError: newBaseError(NumErrInvalidBasicConstraints, "invalid basic constraints")}
}

type ErrInvalidSAN struct{ BaseError }

func NewErrInvalidSAN() Kerror {
	return &ErrInvalidSAN{BaseError: newBaseError(NumErrInvalidSAN, "invalid subject alternative name")}
}

type ErrMalformedSANOtherName struct{ BaseError }

func NewErrMalformedSANOtherName(v any) Kerror {
	if v == nil {
		return &ErrMalformedSANOtherName{BaseError: newBaseError(NumErrMalformedSANOtherName, "malformed SAN otherName")}
	}
	return &ErrMalformedSANOtherName{BaseError: newBaseErrorData(NumErrMalformedSANOtherName, "malformed SAN otherName", v)}
}

type ErrMalformedRfc822Name struct{ BaseError }

func NewErrMalformedRfc822Name() Kerror {
	return &ErrMalformedRfc822Name{BaseError: newBaseError(NumErrMalformedRfc822Name, "malformed rfc822Name")}
}

type ErrMalformedSANDnsName struct{ BaseError }

func NewErrMalformedSANDnsName() Kerror {
	return &ErrMalformedSANDnsName{BaseError: newBaseError(NumErrMalformedSANDnsName, "malformed SAN DNSName")}
}

type ErrMalformedSANDirectoryName struct{ BaseError }

func NewErrMalformedSANDirectoryName() Kerror {
	return &ErrMalformedSANDirectoryName{BaseError: newBaseError(NumErrMalformedSANDirectoryName, "malformed SAN directoryName")}
}

type ErrMalformedSANURI struct{ BaseError }

func NewErrMalformedSANURI() Kerror {
	return &ErrMalformedSANURI{BaseError: newBaseError(NumErrMalformedSANURI, "malformed SAN uniformResourceIdentifier")}
}

type ErrParsingURI struct{ BaseError }

func NewErrParsingURI(val ...any) Kerror {
	return &ErrParsingURI{BaseError: newBaseErrorData(NumErrParsingURI, "cannot parse URI %q: %s", val...)}
}

type ErrParsingIpAddress struct{ BaseError }

func NewErrParsingIpAddress(val ...any) Kerror {
	return &ErrParsingIpAddress{BaseError: newBaseErrorData(NumErrParsingIpAddress, "cannot parse IP address of length %d", val...)}
}

type ErrMalformedRegisterID struct{ BaseError }

func NewErrMalformedRegisterID() Kerror {
	return &ErrMalformedRegisterID{BaseError: newBaseError(NumErrMalformedRegisterID, "malformed SAN registerID")}
}

type ErrInvalidEKU struct{ BaseError }

func NewErrInvalidEKU() Kerror {
	return &ErrInvalidEKU{BaseError: newBaseError(NumErrInvalidEKU, "invalid extended key usages")}
}

type ErrInvalidCertificatePolices struct{ BaseError }

func NewErrInvalidCertificatePolices() Kerror {
	return &ErrInvalidCertificatePolices{BaseError: newBaseError(NumErrInvalidCertificatePolices, "invalid certificate policies")}
}

type ErrInvalidNameConstraintsExtension struct{ BaseError }

func NewErrInvalidNameConstraintsExtension() Kerror {
	return &ErrInvalidNameConstraintsExtension{BaseError: newBaseError(NumErrInvalidNameConstraintsExtension, "invalid NameConstraints extension")}
}

type ErrEmptyNameConstraintsExtension struct{ BaseError }

func NewErrEmptyNameConstraintsExtension() Kerror {
	return &ErrEmptyNameConstraintsExtension{BaseError: newBaseError(NumErrEmptyNameConstraintsExtension, "empty name constraints")}
}

type ErrInvalidConstraintValue struct{ BaseError }

func NewErrInvalidConstraintValue(val ...any) Kerror {
	return &ErrInvalidConstraintValue{BaseError: newBaseErrorData(NumErrInvalidConstraintValue, "failed to parse dnsName constraint: %v", val...)}
}

type ErrIPContraintValueLen struct{ BaseError }

func NewErrIPContraintValueLen(val ...any) Kerror {
	return &ErrIPContraintValueLen{BaseError: newBaseErrorData(NumErrIPContraintValueLen, "IP constraint contained value of length %d", val...)}
}

type ErrIPContraintInvalidMask struct{ BaseError }

func NewErrIPContraintInvalidMask(val ...any) Kerror {
	return &ErrIPContraintInvalidMask{BaseError: newBaseErrorData(NumErrIPContraintInvalidMask, "IP constraint contained invalid mask %x", val...)}
}

type ErrParsingRfc822NameConstraint struct{ BaseError }

func NewErrParsingRfc822NameConstraint(val ...any) Kerror {
	return &ErrParsingRfc822NameConstraint{BaseError: newBaseErrorData(NumErrParsingRfc822NameConstraint, "failed to parse rfc822Name constraint %q", val...)}
}

type ErrParsingURIConstraint struct{ BaseError }

func NewErrParsingURIConstraint(val ...any) Kerror {
	return &ErrParsingURIConstraint{BaseError: newBaseErrorData(NumErrParsingURIConstraint, "failed to parse URI constraint %q", val...)}
}

type ErrInvalidCRLDP struct{ BaseError }

func NewErrInvalidCRLDP() Kerror {
	return &ErrInvalidCRLDP{BaseError: newBaseError(NumErrInvalidCRLDP, "invalid CRL distribution points")}
}

type ErrInvalidPolicyConstraintsExtension struct{ BaseError }

func NewErrInvalidPolicyConstraintsExtension() Kerror {
	return &ErrInvalidPolicyConstraintsExtension{BaseError: newBaseError(NumErrInvalidPolicyConstraintsExtension, "invalid policy constraints extension")}
}

type ErrPolicyConstraintsRequireExplicitPolicyField struct{ BaseError }

func NewErrPolicyConstraintsRequireExplicitPolicyField() Kerror {
	return &ErrPolicyConstraintsRequireExplicitPolicyField{BaseError: newBaseError(NumErrPolicyConstraintsRequireExplicitPolicyField, "policy constraints requireExplicitPolicy field overflows int")}
}

type ErrPolicyConstraintsInhibitPolicyMappingField struct{ BaseError }

func NewErrPolicyConstraintsInhibitPolicyMappingField() Kerror {
	return &ErrPolicyConstraintsInhibitPolicyMappingField{BaseError: newBaseError(NumErrPolicyConstraintsInhibitPolicyMappingField, "policy constraints inhibitPolicyMapping field overflows int")}
}

type ErrSKIIncorrectlyMarkedCritical struct{ BaseError }

func NewErrSKIIncorrectlyMarkedCritical() Kerror {
	return &ErrSKIIncorrectlyMarkedCritical{BaseError: newBaseError(NumErrSKIIncorrectlyMarkedCritical, "subject key identifier incorrectly marked critical")}
}

type ErrInvalidSKI struct{ BaseError }

func NewErrInvalidSKI() Kerror {
	return &ErrInvalidSKI{BaseError: newBaseError(NumErrInvalidSKI, "invalid subject key identifier")}
}

type ErrInvalidPolicyMappingsExtension struct{ BaseError }

func NewErrInvalidPolicyMappingsExtension() Kerror {
	return &ErrInvalidPolicyMappingsExtension{BaseError: newBaseError(NumErrInvalidPolicyMappingsExtension, "invalid policy mappings extension")}
}

type ErrInvalidInhibitAnyPolicyExtension struct{ BaseError }

func NewErrInvalidInhibitAnyPolicyExtension() Kerror {
	return &ErrInvalidInhibitAnyPolicyExtension{BaseError: newBaseError(NumErrInvalidInhibitAnyPolicyExtension, "invalid inhibit any policy extension")}
}

type ErrAuthorityInfoAccessMarkedCritical struct{ BaseError }

func NewErrAuthorityInfoAccessMarkedCritical() Kerror {
	return &ErrAuthorityInfoAccessMarkedCritical{BaseError: newBaseError(NumErrAuthorityInfoAccessMarkedCritical, "authority info access incorrectly marked critical")}
}

type ErrInvalidAuthorityInfoAccess struct{ BaseError }

func NewErrInvalidAuthorityInfoAccess() Kerror {
	return &ErrInvalidAuthorityInfoAccess{BaseError: newBaseError(NumErrInvalidAuthorityInfoAccess, "invalid authority info access")}
}

type ErrMalformedCertificate struct{ BaseError }

func NewErrMalformedCertificate() Kerror {
	return &ErrMalformedCertificate{BaseError: newBaseError(NumErrMalformedCertificate, "malformed certificate")}
}

type ErrMalformedTbsCertificate struct{ BaseError }

func NewErrMalformedTbsCertificate() Kerror {
	return &ErrMalformedTbsCertificate{BaseError: newBaseError(NumErrMalformedTbsCertificate, "malformed tbs certificate")}
}

type ErrMalformedVersion struct{ BaseError }

func NewErrMalformedVersion() Kerror {
	return &ErrMalformedVersion{BaseError: newBaseError(NumErrMalformedVersion, "malformed/invalid version")}
}

type ErrMalformedSignatureAlgorithmIdentifier struct{ BaseError }

func NewErrMalformedSignatureAlgorithmIdentifier() Kerror {
	return &ErrMalformedSignatureAlgorithmIdentifier{BaseError: newBaseError(NumErrMalformedSignatureAlgorithmIdentifier, "malformed signature algorithm identifier")}
}

type ErrInnerOuterSignatureIdentifiersDontMatch struct{ BaseError }

func NewErrInnerOuterSignatureIdentifiersDontMatch() Kerror {
	return &ErrInnerOuterSignatureIdentifiersDontMatch{BaseError: newBaseError(NumErrInnerOuterSignatureIdentifiersDontMatch, "inner and outer signature algorithm identifiers don't match")}
}

type ErrMalformedIssuer struct{ BaseError }

func NewErrMalformedIssuer() Kerror {
	return &ErrMalformedIssuer{BaseError: newBaseError(NumErrMalformedIssuer, "malformed issuer")}
}

type ErrMalformedSPKI struct{ BaseError }

func NewErrMalformedSPKI() Kerror {
	return &ErrMalformedSPKI{BaseError: newBaseError(NumErrMalformedSPKI, "malformed spki")}
}

type ErrMalformedValidity struct{ BaseError }

func NewErrMalformedValidity() Kerror {
	return &ErrMalformedValidity{BaseError: newBaseError(NumErrMalformedValidity, "malformed validity")}
}

type ErrMalformedpublicKeyAlgorithmIdentifier struct{ BaseError }

func NewErrMalformedpublicKeyAlgorithmIdentifier() Kerror {
	return &ErrMalformedpublicKeyAlgorithmIdentifier{BaseError: newBaseError(NumErrMalformedpublicKeyAlgorithmIdentifier, "malformed public key algorithm identifier")}
}

type ErrMalformedSubjectPublicKey struct{ BaseError }

func NewErrMalformedSubjectPublicKey() Kerror {
	return &ErrMalformedSubjectPublicKey{BaseError: newBaseError(NumErrMalformedSubjectPublicKey, "malformed subjectPublicKey")}
}

type ErrMalformedIssuerUniqueID struct{ BaseError }

func NewErrMalformedIssuerUniqueID() Kerror {
	return &ErrMalformedIssuerUniqueID{BaseError: newBaseError(NumErrMalformedIssuerUniqueID, "malformed issuerUniqueID")}
}

type ErrMalformedSubjectUniqueID struct{ BaseError }

func NewErrMalformedSubjectUniqueID() Kerror {
	return &ErrMalformedSubjectUniqueID{BaseError: newBaseError(NumErrMalformedSubjectUniqueID, "malformed subjectUniqueID")}
}

type ErrCertificateContainsDuplicateExtension struct{ BaseError }

func NewErrCertificateContainsDuplicateExtension(val ...any) Kerror {
	return &ErrCertificateContainsDuplicateExtension{BaseError: newBaseErrorData(NumErrCertificateContainsDuplicateExtension, "certificate contains duplicate extension with OID %q", val...)}
}

type ErrMalformedSignature struct{ BaseError }

func NewErrMalformedSignature() Kerror {
	return &ErrMalformedSignature{BaseError: newBaseError(NumErrMalformedSignature, "malformed signature")}
}
