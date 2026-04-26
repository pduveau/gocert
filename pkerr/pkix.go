package pkerr

// ErrUnsupportedAlgorithm results from attempting to perform an operation that
// involves algorithms that are not currently implemented.
type ErrUnsupportedAlgorithm struct{ BaseError }

func NewErrUnsupportedAlgorithm(detail ...any) Kerror {
	if len(detail) > 0 {
		return &ErrUnsupportedAlgorithm{BaseError: NewBaseErrorData(0, "unsuported algorithm %v", detail...)}
	}
	return &ErrUnsupportedAlgorithm{BaseError: NewBaseError(0, "unsuported algorithm")}
}

type ErrSignaturePublicKeyAlgoMismatch struct{ BaseError }

func NewErrSignaturePublicKeyAlgoMismatch(algo string, key any) Kerror {
	return &ErrSignaturePublicKeyAlgoMismatch{BaseError: NewBaseErrorData(0,
		"signature algorithm specifies an %s public key, but have public key of type %T", key, algo)}
}

type ErrECDSAVerificationFailure struct{ BaseError }

func NewErrECDSAVerificationFailure(detail string) Kerror {
	return &ErrSignaturePublicKeyAlgoMismatch{BaseError: NewBaseErrorData(0, "%s verification failure", detail)}
}

type ErrUnsupporteEllipticCurve struct{ BaseError }

func NewErrUnsupporteEllipticCurve() Kerror {
	return &ErrUnsupporteEllipticCurve{BaseError: NewBaseError(0, "unsupported elliptic curve")}
}

type ErrRSAECDSAED25519 struct{ BaseError }

func NewErrRSAECDSAED25519() Kerror {
	return &ErrRSAECDSAED25519{BaseError: NewBaseError(0, "unknown SignatureAlgorithm")}
}

type ErrUnknownSignatureAlgorithm struct{ BaseError }

func NewErrUnknownSignatureAlgorithm(detail ...any) Kerror {
	if len(detail) > 1 {
		return &ErrUnknownSignatureAlgorithm{BaseError: NewBaseErrorData(0, "unknown Signature Algorithm: %s", detail...)}
	}
	return &ErrUnknownSignatureAlgorithm{BaseError: NewBaseError(0, "unknown Signature Algorithm")}
}

type ErrOIDConvert struct{ BaseError }

func NewErrOIDConvert() Kerror {
	return &ErrOIDConvert{BaseError: NewBaseError(0, "cannot convert hash to oid, unknown hash algorithm")}
}

type ErrOIDInvalid struct{ BaseError }

func NewErrOIDInvalid(oid ...any) Kerror {
	if len(oid) > 0 {
		return &ErrOIDInvalid{BaseError: NewBaseErrorData(0, "invalid oid %v", oid...)}
	}
	return &ErrOIDInvalid{BaseError: NewBaseError(0, "invalid oid")}
}

type ErrInsecureAlgorithm struct{ BaseError }

func NewErrInsecureAlgorithm(detail string) Kerror {
	return &ErrInsecureAlgorithm{BaseError: NewBaseErrorData(0, "cannot verify signature: insecure algorithm %s", detail)}
}

type ErrInvalidSignature struct{ BaseError }

func NewErrInvalidSignature(detail string) Kerror {
	return &ErrInvalidSignature{BaseError: NewBaseErrorData(0, "signature is invalid: %s", detail)}
}

type ErrUnsetKey struct{ BaseError }

func NewErrUnsetKey() Kerror {
	return &ErrUnsetKey{BaseError: NewBaseError(0, "unset key")}
}

type ErrUnsupportedDigestForEcryptionAlgorithm struct{ BaseError }

func NewErrUnsupportedDigestForEcryptionAlgorithm(detail ...any) Kerror {
	return &ErrUnsupportedDigestForEcryptionAlgorithm{BaseError: NewBaseErrorData(0, "unsupported digest %q for encryption algorithm %q", detail...)}
}

type ErrConvertEncryptionAlgorithmToOid struct{ BaseError }

func NewErrConvertEncryptionAlgorithmToOid(detail ...any) Kerror {
	return &ErrConvertEncryptionAlgorithmToOid{BaseError: NewBaseErrorData(0, "cannot convert encryption algorithm to oid, unknown private key type %T", detail...)}
}
