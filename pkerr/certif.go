package pkerr

type ErrAKICritical struct{ BaseError }

func NewErrAKICritical() Kerror {
	return &ErrAKICritical{BaseError: NewBaseError(NumErrAKICritical, "authority key identifier incorrectly marked critical")}
}

type ErrInvalidAKI struct{ BaseError }

func NewErrInvalidAKI() Kerror {
	return &ErrInvalidAKI{BaseError: NewBaseError(NumErrInvalidAKI, "invalid authority key identifier")}
}

type ErrInvalidASN1OID struct{ BaseError }

func NewErrInvalidASN1OID() Kerror {
	return &ErrInvalidASN1OID{BaseError: NewBaseError(NumErrInvalidASN1OID, "invalid/malformed OID")}
}

type ErrInvalidASN1Params struct{ BaseError }

func NewErrInvalidASN1Params() Kerror {
	return &ErrInvalidASN1Params{BaseError: NewBaseError(NumErrInvalidASN1Params, "invalid/malformed parameters")}
}

type ErrInvalidASN1Critical struct{ BaseError }

func NewErrInvalidASN1Critical() Kerror {
	return &ErrInvalidASN1Critical{BaseError: NewBaseError(NumErrInvalidASN1Critical, "invalid/malformed critical field")}
}

type ErrInvalidASN1Value struct{ BaseError }

func NewErrInvalidASN1Value() Kerror {
	return &ErrInvalidASN1Value{BaseError: NewBaseError(NumErrInvalidASN1Value, "invalid/malformed value field")}
}

type ErrConstraintViolation struct{ BaseError }

func NewErrConstraintViolation() Kerror {
	return &ErrConstraintViolation{BaseError: NewBaseError(NumErrConstraintViolation, "invalid signature: parent certificate cannot sign this kind of certificate")}
}

type ErrInvalidIssuer struct{ BaseError }

func NewErrInvalidIssuer() Kerror {
	return &ErrInvalidIssuer{BaseError: NewBaseError(NumErrInvalidIssuer, "malformed issuer")}
}

type ErrMalformedSerialNumber struct{ BaseError }

func NewErrMalformedSerialNumber() Kerror {
	return &ErrMalformedSerialNumber{BaseError: NewBaseError(NumErrMalformedSerialNumber, "malformed serial number")}
}

type ErrMalformedExtensions struct{ BaseError }

func NewErrMalformedExtensions() Kerror {
	return &ErrMalformedExtensions{BaseError: NewBaseError(NumErrMalformedExtensions, "malformed extensions")}
}

type ErrUnhandledCriticalExtension struct{ BaseError }

func NewErrUnhandledCriticalExtension() Kerror {
	return &ErrUnhandledCriticalExtension{BaseError: NewBaseError(NumErrUnhandledCriticalExtension, "unhandled critical extension")}
}

type ErrASN1TrailingData struct{ BaseError }

func NewErrASN1TrailingData(where string) Kerror {
	return &ErrASN1TrailingData{BaseError: NewBaseErrorData(NumErrASN1TrailingData, "trailing data after ASN.1 of %s", where)}
}

type ErrUnknownEKU struct{ BaseError }

func NewErrUnknownEKU() Kerror {
	return &ErrUnknownEKU{BaseError: NewBaseError(NumErrUnknownEKU, "unknown extended key usage")}
}

type ErrPublicKeyTypeNoEqual struct{ BaseError }

func NewErrPublicKeyTypeNoEqual() Kerror {
	return &ErrPublicKeyTypeNoEqual{BaseError: NewBaseError(NumErrPublicKeyTypeNoEqual, "supported public key does not implement Equal")}
}

type ErrPrivateKeyDoesNotMatchParentPublicKey struct{ BaseError }

func NewErrPrivateKeyDoesNotMatchParentPublicKey() Kerror {
	return &ErrPrivateKeyDoesNotMatchParentPublicKey{BaseError: NewBaseError(NumErrPrivateKeyDoesNotMatchParentPublicKey, "provided PrivateKey doesn't match parent's PublicKey")}
}

type ErrSerialNumberNegative struct{ BaseError }

func NewErrSerialNumberNegative() Kerror {
	return &ErrSerialNumberNegative{BaseError: NewBaseError(NumErrSerialNumberNegative, "serial number must be positive")}
}

type ErrMaxPathLenNegative struct{ BaseError }

func NewErrMaxPathLenNegative() Kerror {
	return &ErrMaxPathLenNegative{BaseError: NewBaseError(NumErrMaxPathLenNegative, "invalid MaxPathLen, must be greater or equal to -1")}
}

type ErrMaxPathLenOnlyCA struct{ BaseError }

func NewErrMaxPathLenOnlyCA() Kerror {
	return &ErrMaxPathLenOnlyCA{BaseError: NewBaseError(NumErrMaxPathLenOnlyCA, "only CAs are allowed to specify MaxPathLen")}
}

type ErrInvalidKeyUsage struct{ BaseError }

func NewErrInvalidKeyUsage() Kerror {
	return &ErrInvalidKeyUsage{BaseError: NewBaseError(NumErrInvalidKeyUsage, "invalid key usage")}
}

type ErrInvalidBasicConstraints struct{ BaseError }

func NewErrInvalidBasicConstraints() Kerror {
	return &ErrInvalidBasicConstraints{BaseError: NewBaseError(NumErrInvalidBasicConstraints, "invalid basic constraints")}
}

type ErrInvalidSAN struct{ BaseError }

func NewErrInvalidSAN() Kerror {
	return &ErrInvalidSAN{BaseError: NewBaseError(NumErrInvalidSAN, "invalid subject alternative name")}
}

type ErrMalformedSANOtherName struct{ BaseError }

func NewErrMalformedSANOtherName(v any) Kerror {
	if v == nil {
		return &ErrMalformedSANOtherName{BaseError: NewBaseError(NumErrMalformedSANOtherName, "malformed SAN otherName")}
	}
	return &ErrMalformedSANOtherName{BaseError: NewBaseErrorData(NumErrMalformedSANOtherName, "malformed SAN otherName", v)}
}

type ErrMalformedRfc822Name struct{ BaseError }

func NewErrMalformedRfc822Name() Kerror {
	return &ErrMalformedRfc822Name{BaseError: NewBaseError(NumErrMalformedRfc822Name, "malformed rfc822Name")}
}

type ErrMalformedSANDnsName struct{ BaseError }

func NewErrMalformedSANDnsName() Kerror {
	return &ErrMalformedSANDnsName{BaseError: NewBaseError(NumErrMalformedSANDnsName, "malformed SAN DNSName")}
}

type ErrMalformedSANDirectoryName struct{ BaseError }

func NewErrMalformedSANDirectoryName() Kerror {
	return &ErrMalformedSANDirectoryName{BaseError: NewBaseError(NumErrMalformedSANDirectoryName, "malformed SAN directoryName")}
}

type ErrMalformedSANURI struct{ BaseError }

func NewErrMalformedSANURI() Kerror {
	return &ErrMalformedSANURI{BaseError: NewBaseError(NumErrMalformedSANURI, "malformed SAN uniformResourceIdentifier")}
}

type ErrParsingURI struct{ BaseError }

func NewErrParsingURI(val ...any) Kerror {
	return &ErrParsingURI{BaseError: NewBaseErrorData(NumErrParsingURI, "cannot parse URI %q: %s", val...)}
}

type ErrParsingIpAddress struct{ BaseError }

func NewErrParsingIpAddress(val ...any) Kerror {
	return &ErrParsingIpAddress{BaseError: NewBaseErrorData(NumErrParsingIpAddress, "cannot parse IP address of length %d", val...)}
}

type ErrMalformedRegisterID struct{ BaseError }

func NewErrMalformedRegisterID() Kerror {
	return &ErrMalformedRegisterID{BaseError: NewBaseError(NumErrMalformedRegisterID, "malformed SAN registerID")}
}

type ErrInvalidEKU struct{ BaseError }

func NewErrInvalidEKU() Kerror {
	return &ErrInvalidEKU{BaseError: NewBaseError(NumErrInvalidEKU, "invalid extended key usages")}
}

type ErrInvalidCertificatePolices struct{ BaseError }

func NewErrInvalidCertificatePolices() Kerror {
	return &ErrInvalidCertificatePolices{BaseError: NewBaseError(NumErrInvalidCertificatePolices, "invalid certificate policies")}
}

type ErrInvalidNameConstraintsExtension struct{ BaseError }

func NewErrInvalidNameConstraintsExtension() Kerror {
	return &ErrInvalidNameConstraintsExtension{BaseError: NewBaseError(NumErrInvalidNameConstraintsExtension, "invalid NameConstraints extension")}
}

type ErrEmptyNameConstraintsExtension struct{ BaseError }

func NewErrEmptyNameConstraintsExtension() Kerror {
	return &ErrEmptyNameConstraintsExtension{BaseError: NewBaseError(NumErrEmptyNameConstraintsExtension, "empty name constraints")}
}

type ErrInvalidConstraintValue struct{ BaseError }

func NewErrInvalidConstraintValue(val ...any) Kerror {
	return &ErrInvalidConstraintValue{BaseError: NewBaseErrorData(NumErrInvalidConstraintValue, "failed to parse dnsName constraint: %v", val...)}
}

type ErrIPContraintValueLen struct{ BaseError }

func NewErrIPContraintValueLen(val ...any) Kerror {
	return &ErrIPContraintValueLen{BaseError: NewBaseErrorData(NumErrIPContraintValueLen, "IP constraint contained value of length %d", val...)}
}

type ErrIPContraintInvalidMask struct{ BaseError }

func NewErrIPContraintInvalidMask(val ...any) Kerror {
	return &ErrIPContraintInvalidMask{BaseError: NewBaseErrorData(NumErrIPContraintInvalidMask, "IP constraint contained invalid mask %x", val...)}
}

type ErrParsingRfc822NameConstraint struct{ BaseError }

func NewErrParsingRfc822NameConstraint(val ...any) Kerror {
	return &ErrParsingRfc822NameConstraint{BaseError: NewBaseErrorData(NumErrParsingRfc822NameConstraint, "failed to parse rfc822Name constraint %q", val...)}
}

type ErrParsingURIConstraint struct{ BaseError }

func NewErrParsingURIConstraint(val ...any) Kerror {
	return &ErrParsingURIConstraint{BaseError: NewBaseErrorData(NumErrParsingURIConstraint, "failed to parse URI constraint %q", val...)}
}

type ErrInvalidCRLDP struct{ BaseError }

func NewErrInvalidCRLDP() Kerror {
	return &ErrInvalidCRLDP{BaseError: NewBaseError(NumErrInvalidCRLDP, "invalid CRL distribution points")}
}

type ErrInvalidPolicyConstraintsExtension struct{ BaseError }

func NewErrInvalidPolicyConstraintsExtension() Kerror {
	return &ErrInvalidPolicyConstraintsExtension{BaseError: NewBaseError(NumErrInvalidPolicyConstraintsExtension, "invalid policy constraints extension")}
}

type ErrPolicyConstraintsRequireExplicitPolicyField struct{ BaseError }

func NewErrPolicyConstraintsRequireExplicitPolicyField() Kerror {
	return &ErrPolicyConstraintsRequireExplicitPolicyField{BaseError: NewBaseError(NumErrPolicyConstraintsRequireExplicitPolicyField, "policy constraints requireExplicitPolicy field overflows int")}
}

type ErrPolicyConstraintsInhibitPolicyMappingField struct{ BaseError }

func NewErrPolicyConstraintsInhibitPolicyMappingField() Kerror {
	return &ErrPolicyConstraintsInhibitPolicyMappingField{BaseError: NewBaseError(NumErrPolicyConstraintsInhibitPolicyMappingField, "policy constraints inhibitPolicyMapping field overflows int")}
}

type ErrSKIIncorrectlyMarkedCritical struct{ BaseError }

func NewErrSKIIncorrectlyMarkedCritical() Kerror {
	return &ErrSKIIncorrectlyMarkedCritical{BaseError: NewBaseError(NumErrSKIIncorrectlyMarkedCritical, "subject key identifier incorrectly marked critical")}
}

type ErrInvalidSKI struct{ BaseError }

func NewErrInvalidSKI() Kerror {
	return &ErrInvalidSKI{BaseError: NewBaseError(NumErrInvalidSKI, "invalid subject key identifier")}
}

type ErrInvalidPolicyMappingsExtension struct{ BaseError }

func NewErrInvalidPolicyMappingsExtension() Kerror {
	return &ErrInvalidPolicyMappingsExtension{BaseError: NewBaseError(NumErrInvalidPolicyMappingsExtension, "invalid policy mappings extension")}
}

type ErrInvalidInhibitAnyPolicyExtension struct{ BaseError }

func NewErrInvalidInhibitAnyPolicyExtension() Kerror {
	return &ErrInvalidInhibitAnyPolicyExtension{BaseError: NewBaseError(NumErrInvalidInhibitAnyPolicyExtension, "invalid inhibit any policy extension")}
}

type ErrAuthorityInfoAccessMarkedCritical struct{ BaseError }

func NewErrAuthorityInfoAccessMarkedCritical() Kerror {
	return &ErrAuthorityInfoAccessMarkedCritical{BaseError: NewBaseError(NumErrAuthorityInfoAccessMarkedCritical, "authority info access incorrectly marked critical")}
}

type ErrInvalidAuthorityInfoAccess struct{ BaseError }

func NewErrInvalidAuthorityInfoAccess() Kerror {
	return &ErrInvalidAuthorityInfoAccess{BaseError: NewBaseError(NumErrInvalidAuthorityInfoAccess, "invalid authority info access")}
}

type ErrMalformedCertificate struct{ BaseError }

func NewErrMalformedCertificate() Kerror {
	return &ErrMalformedCertificate{BaseError: NewBaseError(NumErrMalformedCertificate, "malformed certificate")}
}

type ErrMalformedTbsCertificate struct{ BaseError }

func NewErrMalformedTbsCertificate() Kerror {
	return &ErrMalformedTbsCertificate{BaseError: NewBaseError(NumErrMalformedTbsCertificate, "malformed tbs certificate")}
}

type ErrMalformedVersion struct{ BaseError }

func NewErrMalformedVersion() Kerror {
	return &ErrMalformedVersion{BaseError: NewBaseError(NumErrMalformedVersion, "malformed/invalid version")}
}

type ErrMalformedSignatureAlgorithmIdentifier struct{ BaseError }

func NewErrMalformedSignatureAlgorithmIdentifier() Kerror {
	return &ErrMalformedSignatureAlgorithmIdentifier{BaseError: NewBaseError(NumErrMalformedSignatureAlgorithmIdentifier, "malformed signature algorithm identifier")}
}

type ErrInnerOuterSignatureIdentifiersDontMatch struct{ BaseError }

func NewErrInnerOuterSignatureIdentifiersDontMatch() Kerror {
	return &ErrInnerOuterSignatureIdentifiersDontMatch{BaseError: NewBaseError(NumErrInnerOuterSignatureIdentifiersDontMatch, "inner and outer signature algorithm identifiers don't match")}
}

type ErrMalformedIssuer struct{ BaseError }

func NewErrMalformedIssuer() Kerror {
	return &ErrMalformedIssuer{BaseError: NewBaseError(NumErrMalformedIssuer, "malformed issuer")}
}

type ErrMalformedSPKI struct{ BaseError }

func NewErrMalformedSPKI() Kerror {
	return &ErrMalformedSPKI{BaseError: NewBaseError(NumErrMalformedSPKI, "malformed spki")}
}

type ErrMalformedValidity struct{ BaseError }

func NewErrMalformedValidity() Kerror {
	return &ErrMalformedValidity{BaseError: NewBaseError(NumErrMalformedValidity, "malformed validity")}
}

type ErrMalformedpublicKeyAlgorithmIdentifier struct{ BaseError }

func NewErrMalformedpublicKeyAlgorithmIdentifier() Kerror {
	return &ErrMalformedpublicKeyAlgorithmIdentifier{BaseError: NewBaseError(NumErrMalformedpublicKeyAlgorithmIdentifier, "malformed public key algorithm identifier")}
}

type ErrMalformedSubjectPublicKey struct{ BaseError }

func NewErrMalformedSubjectPublicKey() Kerror {
	return &ErrMalformedSubjectPublicKey{BaseError: NewBaseError(NumErrMalformedSubjectPublicKey, "malformed subjectPublicKey")}
}

type ErrMalformedIssuerUniqueID struct{ BaseError }

func NewErrMalformedIssuerUniqueID() Kerror {
	return &ErrMalformedIssuerUniqueID{BaseError: NewBaseError(NumErrMalformedIssuerUniqueID, "malformed issuerUniqueID")}
}

type ErrMalformedSubjectUniqueID struct{ BaseError }

func NewErrMalformedSubjectUniqueID() Kerror {
	return &ErrMalformedSubjectUniqueID{BaseError: NewBaseError(NumErrMalformedSubjectUniqueID, "malformed subjectUniqueID")}
}

type ErrCertificateContainsDuplicateExtension struct{ BaseError }

func NewErrCertificateContainsDuplicateExtension(val ...any) Kerror {
	return &ErrCertificateContainsDuplicateExtension{BaseError: NewBaseErrorData(NumErrCertificateContainsDuplicateExtension, "certificate contains duplicate extension with OID %q", val...)}
}

type ErrMalformedSignature struct{ BaseError }

func NewErrMalformedSignature() Kerror {
	return &ErrMalformedSignature{BaseError: NewBaseError(NumErrMalformedSignature, "malformed signature")}
}
