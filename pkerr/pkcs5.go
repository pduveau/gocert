package pkerr

type ErrUnsupportedPBMAC1Algorithm struct{ BaseError }

func NewErrUnsupportedPBMAC1Algorithm(algo string) Kerror {
	return &ErrUnsupportedPBMAC1Algorithm{BaseError: newBaseErrorData(NumErrUnsupportedPBMAC1Algorithm, "PBMAC1 MAC algorithm %s is not supported", algo)}
}

type ErrUnsupportedEncryptionAlgorithm struct{ BaseError }

func NewErrUnsupportedEncryptionAlgorithm(algo string) Kerror {
	return &ErrUnsupportedEncryptionAlgorithm{BaseError: newBaseErrorData(NumErrUnsupportedEncryptionAlgorithm, "unsupported encryption algorithm (%s)", algo)}
}

type ErrInvalidKDFParams struct{ BaseError }

func NewErrInvalidKDFParams(v any) Kerror {
	return &ErrInvalidKDFParams{BaseError: newBaseErrorData(NumErrInvalidKDFParams, "invalid KDF parameters (%v)", v)}
}

type ErrInvalidPBES2Params struct{ BaseError }

func NewErrInvalidPBES2Params() Kerror {
	return &ErrInvalidPBES2Params{BaseError: newBaseError(NumErrInvalidPBES2Params, "invalid PBES2 parameters")}
}

type ErrEmptySalt struct{ BaseError }

func NewErrEmptySalt() Kerror {
	return &ErrEmptySalt{BaseError: newBaseError(NumErrEmptySalt, "salt is empty")}
}

type ErrUnsupportedHash struct{ BaseError }

func NewErrUnsupportedHash() Kerror {
	return &ErrUnsupportedHash{BaseError: newBaseError(NumErrUnsupportedHash, "unsupported hash function")}
}

type ErrUnsupportedKDFOid struct{ BaseError }

func NewErrUnsupportedKDFOid(oid string) Kerror {
	return &ErrUnsupportedKDFOid{BaseError: newBaseErrorData(NumErrUnsupportedKDFOid, "unsupported KDF (OID: %s)", oid)}
}

type ErrPasswordMissing struct{ BaseError }

func NewErrPasswordMissing() Kerror {
	return &ErrPasswordMissing{BaseError: newBaseError(NumErrPasswordMissing, "password is required")}
}

type ErrPBES2Only struct{ BaseError }

func NewErrPBES2Only() Kerror {
	return &ErrPBES2Only{BaseError: newBaseError(NumErrPBES2Only, "only PBES2 is supported")}
}
