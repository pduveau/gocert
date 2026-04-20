package pkerr

type ErrParsingRSAPrivateKeyInPKCS8 struct{ BaseError }

func NewErrParsingRSAPrivateKeyInPKCS8(v ...any) Kerror {
	return &ErrParsingRSAPrivateKeyInPKCS8{BaseError: NewBaseErrorData(NumErrParsingRSAPrivateKeyInPKCS8, "failed to parse RSA private key embedded in PKCS#8: %v", v...)}
}

type ErrInvalidEd25519Params struct{ BaseError }

func NewErrInvalidEd25519Params() Kerror {
	return &ErrInvalidEd25519Params{BaseError: NewBaseError(NumErrInvalidEd25519Params, "Ed25519 key encoded with illegal parameters")}
}

type ErrInvalidEd25519PrivateKey struct{ BaseError }

func NewErrInvalidEd25519PrivateKey(v ...any) Kerror {
	return &ErrInvalidEd25519PrivateKey{BaseError: NewBaseErrorData(NumErrInvalidEd25519PrivateKey, "invalid Ed25519 private key: %v", v...)}
}

type ErrInvalidEd25519PrivateKeylen struct{ BaseError }

func NewErrInvalidEd25519PrivateKeylen(l int) Kerror {
	return &ErrInvalidEd25519PrivateKeylen{BaseError: NewBaseErrorData(NumErrInvalidEd25519PrivateKeylen, "invalid Ed25519 private key length: %d", l)}
}

type ErrInvalidX25519Params struct{ BaseError }

func NewErrInvalidX25519Params() Kerror {
	return &ErrInvalidX25519Params{BaseError: NewBaseError(NumErrInvalidX25519Params, "invalid X25519 private key parameters")}
}

type ErrInvalidX25519PrivateKey struct{ BaseError }

func NewErrInvalidX25519PrivateKey(v ...any) Kerror {
	return &ErrInvalidX25519PrivateKey{BaseError: NewBaseErrorData(NumErrInvalidX25519PrivateKey, "invalid X25519 private key: %v", v...)}
}

type ErrPKCS8WrappingUnknownAlgorithm struct{ BaseError }

func NewErrPKCS8WrappingUnknownAlgorithm(v ...any) Kerror {
	return &ErrPKCS8WrappingUnknownAlgorithm{BaseError: NewBaseErrorData(NumErrPKCS8WrappingUnknownAlgorithm, "PKCS#8 wrapping contained private key with unknown algorithm: %v", v...)}
}

type ErrOnlyPKCS5v20 struct{ BaseError }

func NewErrOnlyPKCS5v20() Kerror {
	return &ErrOnlyPKCS5v20{BaseError: NewBaseError(NumErrOnlyPKCS5v20, "only PKCS #5 v2.0 supported")}
}

type ErrUnknownCurveMarshalPKCS8 struct{ BaseError }

func NewErrUnknownCurveMarshalPKCS8() Kerror {
	return &ErrUnknownCurveMarshalPKCS8{BaseError: NewBaseError(NumErrUnknownCurveMarshalPKCS8, "unknown curve while marshaling to PKCS#8")}
}

type ErrMarshalCurveOid struct{ BaseError }

func NewErrMarshalCurveOid(v ...any) Kerror {
	return &ErrMarshalCurveOid{BaseError: NewBaseErrorData(NumErrMarshalCurveOid, "failed to marshal curve OID: %v", v...)}
}

type ErrMarshalPKSC8PrivateKey struct{ BaseError }

func NewErrMarshalPKSC8PrivateKey(v ...any) Kerror {
	return &ErrMarshalPKSC8PrivateKey{BaseError: NewBaseErrorData(NumErrMarshalPKSC8PrivateKey, "failed to marshal %sprivate key while building PKCS#8: %v", v...)}
}

type ErrMarshalPKSC8Curve struct{ BaseError }

func NewErrMarshalPKSC8Curve() Kerror {
	return &ErrMarshalPKSC8Curve{BaseError: NewBaseError(NumErrMarshalPKSC8Curve, "unknown curve while marshaling to PKCS#8")}
}

type ErrMarshalPKCS8ECPrivateKey struct{ BaseError }

func NewErrMarshalPKCS8ECPrivateKey(v ...any) Kerror {
	return &ErrMarshalPKCS8ECPrivateKey{BaseError: NewBaseErrorData(NumErrMarshalPKCS8ECPrivateKey, "failed to marshal EC private key while building PKCS#8: %v", v...)}
}

type ErrMarshalPKCS8KeyType struct{ BaseError }

func NewErrMarshalPKCS8KeyType(v ...any) Kerror {
	return &ErrMarshalPKCS8KeyType{BaseError: NewBaseErrorData(NumErrMarshalPKCS8KeyType, "unknown key type while marshaling PKCS#8: %T", v...)}
}
