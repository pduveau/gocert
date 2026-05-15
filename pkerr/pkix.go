package pkerr

import "fmt"

// ErrUnsupportedAlgorithm results from attempting to perform an operation that
// involves algorithms that are not currently implemented.
type ErrUnsupportedAlgorithm struct{ BaseError }

func NewErrUnsupportedAlgorithm(detail ...any) Kerror {
	if len(detail) > 0 {
		return &ErrUnsupportedAlgorithm{BaseError: newBaseErrorData(NumErrUnsupportedAlgorithm, "unsuported algorithm %v", detail...)}
	}
	return &ErrUnsupportedAlgorithm{BaseError: newBaseError(NumErrUnsupportedAlgorithm, "unsuported algorithm")}
}

type ErrSignaturePublicKeyAlgoMismatch struct{ BaseError }

func NewErrSignaturePublicKeyAlgoMismatch(algo string, key any) Kerror {
	return &ErrSignaturePublicKeyAlgoMismatch{BaseError: newBaseErrorData(0,
		"signature algorithm specifies an %s public key, but have public key of type %T", key, algo)}
}

type ErrECDSAVerificationFailure struct{ BaseError }

func NewErrECDSAVerificationFailure(detail string) Kerror {
	return &ErrSignaturePublicKeyAlgoMismatch{BaseError: newBaseErrorData(NumErrSignaturePublicKeyAlgoMismatch, "%s verification failure", detail)}
}

type ErrUnsupporteEllipticCurve struct{ BaseError }

func NewErrUnsupporteEllipticCurve() Kerror {
	return &ErrUnsupporteEllipticCurve{BaseError: newBaseError(NumErrUnsupporteEllipticCurve, "unsupported elliptic curve")}
}

type ErrRSAECDSAED25519 struct{ BaseError }

func NewErrRSAECDSAED25519() Kerror {
	return &ErrRSAECDSAED25519{BaseError: newBaseError(NumErrRSAECDSAED25519, "unknown SignatureAlgorithm")}
}

type ErrUnknownSignatureAlgorithm struct{ BaseError }

func NewErrUnknownSignatureAlgorithm(detail ...any) Kerror {
	if len(detail) > 1 {
		return &ErrUnknownSignatureAlgorithm{BaseError: newBaseErrorData(NumErrUnknownSignatureAlgorithm, "unknown Signature Algorithm: %s", detail...)}
	}
	return &ErrUnknownSignatureAlgorithm{BaseError: newBaseError(NumErrUnknownSignatureAlgorithm, "unknown Signature Algorithm")}
}

type ErrOIDConvertToAlgorithm struct{ BaseError }

func NewErrOIDConvertToAlgorithm() Kerror {
	return &ErrOIDConvertToAlgorithm{BaseError: newBaseError(NumErrOIDConvertToAlgorithm, "cannot convert hash to oid, unknown hash algorithm")}
}

type ErrOIDInvalid struct{ BaseError }

func NewErrOIDInvalid(oid ...any) Kerror {
	if len(oid) > 0 {
		return &ErrOIDInvalid{BaseError: newBaseErrorData(NumErrOIDInvalid, "invalid oid %v", oid...)}
	}
	return &ErrOIDInvalid{BaseError: newBaseError(NumErrOIDInvalid, "invalid oid")}
}

type ErrInsecureAlgorithm struct{ BaseError }

func NewErrInsecureAlgorithm(detail string) Kerror {
	return &ErrInsecureAlgorithm{BaseError: newBaseErrorData(NumErrInsecureAlgorithm, "cannot verify signature: insecure algorithm %s", detail)}
}

type ErrInvalidSignature struct{ BaseError }

func NewErrInvalidSignature(detail string) Kerror {
	return &ErrInvalidSignature{BaseError: newBaseErrorData(NumErrInvalidSignature, "signature is invalid: %s", detail)}
}

type ErrUnsetKey struct{ BaseError }

func NewErrUnsetKey() Kerror {
	return &ErrUnsetKey{BaseError: newBaseError(NumErrUnsetKey, "unset key")}
}

type ErrUnsupportedDigestForEcryptionAlgorithm struct{ BaseError }

func NewErrUnsupportedDigestForEcryptionAlgorithm(detail ...any) Kerror {
	return &ErrUnsupportedDigestForEcryptionAlgorithm{BaseError: newBaseErrorData(NumErrUnsupportedDigestForEcryptionAlgorithm, "unsupported digest %q for encryption algorithm %q", detail...)}
}

type ErrConvertEncryptionAlgorithmToOid struct{ BaseError }

func NewErrConvertEncryptionAlgorithmToOid(detail ...any) Kerror {
	return &ErrConvertEncryptionAlgorithmToOid{BaseError: newBaseErrorData(NumErrConvertEncryptionAlgorithmToOid, "cannot convert encryption algorithm to oid, unknown private key type %T", detail...)}
}

type ErrParsingOid struct{ BaseError }

func NewErrParsingOid(msg ...any) Kerror {
	if len(msg) > 1 {
		format := fmt.Sprintf("oid invalid: %s", msg[0])
		return &ErrParsingOid{BaseError: newBaseErrorData(NumErrParsingOid, format, msg[1:]...)}
	}
	return &ErrParsingOid{BaseError: newBaseErrorData(NumErrParsingOid, "oid invalid: %s", msg[0])}
}

type ErrDecodeHexValue struct{ BaseError }

func NewErrDecodeHexValue(tn, hx string, err error) Kerror {
	if err == nil {
		return &ErrDecodeHexValue{BaseError: newBaseErrorData(NumErrDecodeHexValue, "hex invalid '%s' for typeName: %s parsing with rest", hx, tn)}
	}
	return &ErrDecodeHexValue{BaseError: newBaseErrorData(NumErrDecodeHexValue, "hex invalid '%s' for typeName: %s (%v)", hx, tn, err)}
}
