package pkerr

type ErrorNumeric int

const (
	NumErrNative ErrorNumeric = iota + 0x200
	// ASN1
	NumErrAsn1TimeSerializationToOriginal
	NumErrAsn1Syntax
	NumErrAsn1Structural
	NumErrAsn1Mashal
	NumErrInvalidUnmarshal

	// certif
	NumErrAKICritical
	NumErrInvalidAKI
	NumErrInvalidASN1OID
	NumErrInvalidASN1Params
	NumErrInvalidASN1Critical
	NumErrInvalidASN1Value
	NumErrConstraintViolation
	NumErrInvalidIssuer
	NumErrMalformedSerialNumber
	NumErrMalformedExtensions
	NumErrUnhandledCriticalExtension
	NumErrASN1TrailingData
	NumErrUnknownEKU
	NumErrPublicKeyTypeNoEqual
	NumErrPrivateKeyDoesNotMatchParentPublicKey
	NumErrSerialNumberNegative
	NumErrMaxPathLenNegative
	NumErrMaxPathLenOnlyCA
	NumErrInvalidKeyUsage
	NumErrInvalidBasicConstraints
	NumErrInvalidSAN
	NumErrMalformedSANOtherName
	NumErrMalformedRfc822Name
	NumErrMalformedSANDnsName
	NumErrMalformedSANDirectoryName
	NumErrMalformedSANURI
	NumErrParsingURI
	NumErrParsingIpAddress
	NumErrMalformedRegisterID
	NumErrInvalidEKU
	NumErrInvalidCertificatePolices
	NumErrInvalidNameConstraintsExtension
	NumErrEmptyNameConstraintsExtension
	NumErrInvalidConstraintValue
	NumErrIPContraintValueLen
	NumErrIPContraintInvalidMask
	NumErrParsingRfc822NameConstraint
	NumErrParsingURIConstraint
	NumErrInvalidCRLDP
	NumErrInvalidPolicyConstraintsExtension
	NumErrPolicyConstraintsRequireExplicitPolicyField
	NumErrPolicyConstraintsInhibitPolicyMappingField
	NumErrSKIIncorrectlyMarkedCritical
	NumErrInvalidSKI
	NumErrInvalidPolicyMappingsExtension
	NumErrInvalidInhibitAnyPolicyExtension
	NumErrAuthorityInfoAccessMarkedCritical
	NumErrInvalidAuthorityInfoAccess
	NumErrMalformedCertificate
	NumErrMalformedTbsCertificate
	NumErrMalformedVersion
	NumErrMalformedSignatureAlgorithmIdentifier
	NumErrInnerOuterSignatureIdentifiersDontMatch
	NumErrMalformedIssuer
	NumErrMalformedSPKI
	NumErrMalformedValidity
	NumErrMalformedpublicKeyAlgorithmIdentifier
	NumErrMalformedSubjectPublicKey
	NumErrMalformedIssuerUniqueID
	NumErrMalformedSubjectUniqueID
	NumErrCertificateContainsDuplicateExtension
	NumErrMalformedSignature

	// crl
	NumErrNilTemplate
	NumErrNilIssuer
	NumErrIssuerWithoutCrlSign
	NumErrIssuerWithoutSKI
	NumErrThisAndNextUpdateOrder
	NumErrNumberNil
	NumErrNilSerialEntries
	NumErrNoRevocationTimeEntries
	NumErrReasonCodeExtraExtensionEntries
	NumErrCRLNumberExceedMaxLength
	NumErrMalformedCrl
	NumErrMalformedTbsCrl
	NumErrUnsupportedCrlVersion
	NumErrInvalidAlgorithmIdentifier
	NumErrInconsistentAlgorithms
	NumErrMalformedCrlNumber

	// internals
	NumErrEncryptionParams
	NumErrEncryptionBocklen
	NumErrEncryptionDatalen
	NumErrEncryptionData
	NumErrEncryptionPadding
	NumErrFailToParsePrivateKeyGotoPKCS1
	NumErrFailToParsePublicKeyGotoPKCS1
	NumErrFailToParsePrivateKeyGotoPKCS8
	NumErrFailToParsePrivateKeyGotoECP
	NumErrFailToParsePrivateKeyGotoPKIX
	NumErrFailToParsePublicKeyGotoPKIX
	NumErrFailToParsePrivateKey
	NumErrUnknownPrivateKeyVersion
	NumErrUnknownEC
	NumErrUnsupportedEC
	NumErrInvalidKeylen
	NumErrRSAMissingParams
	NumErrRSAInvalidPublicKey
	NumErrRSAInvalidModulus
	NumErrRSAInvalidPublicExponent
	NumErrInvalidECDSAParams
	NumErrEd25519Keylen
	NumErrIllegalX25519Params
	NumErrDeprecatedAlgorithm
	NumErrUnknownPubKeyAlgorithm
	NumErrUnsupportedPublicKeyType
	NumErrGeneralizedTime
	NumErrUTCTime
	NumErrHighTagValue
	NumErrBuilderASN1ChildTooLong
	NumErrBuilderASN1ChildExceed
	NumErrBuildASN1Overflow
	NumErrBuildASN1ExceedsBuffer
	NumErrUnsupportedStringType
	NumErrInvalidRDNSequence
	NumErrMalformedGeneralizedTime
	NumErrMalformedUTCTime
	NumErrMalformedTime

	// macos
	NumErrOSStatus
	NumErrMacOSInvalidCertificate
	NumErrMacOSGeneric

	// pem
	NumErrNoDeckInfoInBlock
	NumErrUnknownEncryptionMode
	NumErrIncorrectIVSize
	NumErrEncryptedNotMatchingBlocSizing
	NumErrIVGeneration
	NumErrFailToParsePEM

	// pkcs5
	NumErrUnsupportedPBMAC1Algorithm
	NumErrUnsupportedEncryptionAlgorithm
	NumErrInvalidKDFParams
	NumErrInvalidPBES2Params
	NumErrEmptySalt
	NumErrUnsupportedHash
	NumErrUnsupportedKDFOid
	NumErrPasswordMissing
	NumErrPBES2Only

	// pkcs7
	NumErrCannotDecryptData
	NumErrNotEncryptedContent
	NumErrUnsupportedContentType
	NumErrEmptyInputData
	NumErrParsingBER
	NumErrNoEnvelopForCertificate
	NumErrDecryptableDataType
	NumErrInvalidAlgorithmParams
	NumErrNoPSK
	NumErrInvalidContentEncryptionAlgorithm
	NumErrNoSignerInfo
	NumErrPrivateKeyNotASigner
	NumErrMsgWithoutSigners
	NumErrNoCertificateForSigner
	NumErrMissingAttributType
	NumErrMessageDigestMismatch
	NumErrNoParentToVerify
	NumErrInvalidSignatureByParent
	NumErrSigningTimeOutOfValidity
	NumErrChainVerify
	NumErrMsgHasNoSignedContent
	NumErrNoSignerInformationFound
	NumErrNoCallBackDefined
	NumErrBERTagTooLong
	NumErrBERTagNegativeLength
	NumErrBERTagLeddingZero
	NumErrInvalidBERFormat
	NumErrBERLengthMoreThenData

	// pkcs8
	NumErrParsingRSAPrivateKeyInPKCS8
	NumErrInvalidEd25519Params
	NumErrInvalidEd25519PrivateKey
	NumErrInvalidEd25519PrivateKeylen
	NumErrInvalidX25519Params
	NumErrInvalidX25519PrivateKey
	NumErrPKCS8WrappingUnknownAlgorithm
	NumErrOnlyPKCS5v20
	NumErrUnknownCurveMarshalPKCS8
	NumErrMarshalCurveOid
	NumErrMarshalPKSC8PrivateKey
	NumErrMarshalPKSC8Curve
	NumErrMarshalPKCS8ECPrivateKey
	NumErrMarshalPKCS8KeyType

	// pkcs10
	NumErrDuplicateExtensionInCertificateRequest
	NumErrPrivateKeyIsNotSigner
	NumErrFailtoMarshalExtensions

	// pkcs12
	NumErrCharUnsupportedInUCS2
	NumErrOddLengthBMPString
	NumErrIncorrectPassword
	NumErrDecodingCertBag
	NumErrEncodingCertBag
	NumErrOnlyCertificateInCertBag
	NumErrMacDigestUnsupportedAlgorithm
	NumErrOnlyOneCertificateInCertBag
	NumErrOnlyTwoSafeBags
	NumErrExactlyOneKeyExpected
	NumErrCertificateMissing
	NumErrKeyMissing
	NumErrOnlyTrustedCertificateInTrustStore
	NumErrReadingP12Data
	NumErrOnlyV3PDU
	NumErrOnlyPasswordPFX
	NumErrNoMACinData
	NumErrExpectedExactlyNItems
	NumErrExpectedBetweenNandMItems
	NumErrOnlyVersion0
	NumErrOnlyDataAndEcryptedDataSupported
	NumErrWritingP12Data

	// pkix
	NumErrUnsupportedAlgorithm
	NumErrSignaturePublicKeyAlgoMismatch
	NumErrECDSAVerificationFailure
	NumErrUnsupporteEllipticCurve
	NumErrRSAECDSAED25519
	NumErrUnknownSignatureAlgorithm
	NumErrOIDConvertToAlgorithm
	NumErrOIDInvalid
	NumErrInsecureAlgorithm
	NumErrInvalidSignature
	NumErrUnsetKey
	NumErrUnsupportedDigestForEcryptionAlgorithm
	NumErrConvertEncryptionAlgorithmToOid
	NumErrParsingOid
	NumErrDecodeHexValue

	// pool
	NumErrNotAuthorizedToSign
	// NunErrExpired results when a certificate has expired, based on the time
	// given in the VerifyOptions.
	NunErrExpired
	// NunErrCANotAuthorizedForThisName results when an intermediate or root
	// certificate has a name constraint which doesn't permit a DNS or
	// other name (including IP address) in the leaf certificate.
	NunErrCANotAuthorizedForThisName
	// NunErrTooManyIntermediates results when a path length constraint is
	// violated.
	NunErrTooManyIntermediates
	// NunErrIncompatibleUsage results when the certificate's key usage indicates
	// that it may only be used for a different purpose.
	NunErrIncompatibleUsage
	// NunErrNameMismatch results when the subject name of a parent certificate
	// does not match the issuer name in the child.
	NunErrNameMismatch
	// NunErrNameConstraintsWithoutSANs is a legacy error and is no longer returned.
	NunErrNameConstraintsWithoutSANs
	// NunErrUnconstrainedName results when a CA certificate contains permitted
	// name constraints, but leaf certificate contains a name of an
	// unsupported or unconstrained type.
	NunErrUnconstrainedName
	// NunErrTooManyConstraints results when the number of comparison operations
	// needed to check a certificate exceeds the limit set by
	// VerifyOptions.MaxConstraintComparisions. This limit exists to
	// prevent pathological certificates can consuming excessive amounts of
	// CPU time to verify.
	NunErrTooManyConstraints
	// NunErrCANotAuthorizedForExtKeyUsage results when an intermediate or root
	// certificate does not permit a requested extended key usage.
	NunErrCANotAuthorizedForExtKeyUsage
	// NunErrNoValidChains results when there are no valid chains to return.
	NunErrNoValidChains
	NumErrInvalidSimpleChain
	NumErrSystemRoots
	NumErrEmptyChain
	NumErrInvalidLeafCertificate
	NumErrMacOSInternal

	// verify
	NumErrHostnameLegacyCNField
	NumErrHostnameDoesNotContainIPSAN
	NumErrHostnameNoneIPSANMatched
	NumErrHostnameNoneDNSSANMatched
	NumErrHostnameCertificateNotValidForAnyNames
	NumErrHostnameCertificateValidButNotForName

	NumErrUnknownAuthority
	NumErrSignatureCheckReachDeepLimit
	NumErrCertficateNotParsed
	NumErrFetchingIntermediaries
	NumErrEmptyChainWhileAppending
	NumErrBad
)
