package pkerr

type ErrNilTemplate struct{ BaseError }

func NewErrNilTemplate() Kerror {
	return &ErrNilTemplate{BaseError: newBaseError(NumErrNilTemplate, "template can not be nil")}
}

type ErrNilIssuer struct{ BaseError }

func NewErrNilIssuer() Kerror {
	return &ErrNilIssuer{BaseError: newBaseError(NumErrNilIssuer, "issuer can not be nil")}
}

type ErrIssuerWithoutCrlSign struct{ BaseError }

func NewErrIssuerWithoutCrlSign() Kerror {
	return &ErrIssuerWithoutCrlSign{BaseError: newBaseError(NumErrIssuerWithoutCrlSign, "issuer must have the crlSign key usage bit set")}
}

type ErrIssuerWithoutSKI struct{ BaseError }

func NewErrIssuerWithoutSKI() Kerror {
	return &ErrIssuerWithoutSKI{BaseError: newBaseError(NumErrIssuerWithoutSKI, "issuer certificate doesn't contain a subject key identifier")}
}

type ErrThisAndNextUpdateOrder struct{ BaseError }

func NewErrThisAndNextUpdateOrder() Kerror {
	return &ErrThisAndNextUpdateOrder{BaseError: newBaseError(NumErrThisAndNextUpdateOrder, "template.ThisUpdate is after template.NextUpdate")}
}

type ErrNumberNil struct{ BaseError }

func NewErrNumberNil() Kerror {
	return &ErrNumberNil{BaseError: newBaseError(NumErrNumberNil, "Number field can not be nil")}
}

type ErrNilSerialEntries struct{ BaseError }

func NewErrNilSerialEntries() Kerror {
	return &ErrNilSerialEntries{BaseError: newBaseError(NumErrNilSerialEntries, "template contains entry with nil SerialNumber field")}
}

type ErrNoRevocationTimeEntries struct{ BaseError }

func NewErrNoRevocationTimeEntries() Kerror {
	return &ErrNoRevocationTimeEntries{BaseError: newBaseError(NumErrNoRevocationTimeEntries, "template contains entry with zero RevocationTime field")}
}

type ErrReasonCodeExtraExtensionEntries struct{ BaseError }

func NewErrReasonCodeExtraExtensionEntries() Kerror {
	return &ErrReasonCodeExtraExtensionEntries{BaseError: newBaseError(NumErrReasonCodeExtraExtensionEntries, "template contains entry with ReasonCode ExtraExtension; use ReasonCode field instead")}
}

type ErrCRLNumberExceedMaxLength struct{ BaseError }

func NewErrCRLNumberExceedMaxLength() Kerror {
	return &ErrCRLNumberExceedMaxLength{BaseError: newBaseError(NumErrCRLNumberExceedMaxLength, "CRL number exceeds 20 octets")}
}

type ErrMalformedCrl struct{ BaseError }

func NewErrMalformedCrl() Kerror {
	return &ErrMalformedCrl{BaseError: newBaseError(NumErrMalformedCrl, "malformed crl")}
}

type ErrMalformedTbsCrl struct{ BaseError }

func NewErrMalformedTbsCrl() Kerror {
	return &ErrMalformedTbsCrl{BaseError: newBaseError(NumErrMalformedTbsCrl, "malformed tbs crl")}
}

type ErrUnsupportedCrlVersion struct{ BaseError }

const x509v2Version = 1

func NewErrUnsupportedCrlVersion(version int) Kerror {
	if version == x509v2Version {
		// x509v2Version is the supported one so it can not be the issue
		return &ErrUnsupportedCrlVersion{BaseError: newBaseError(NumErrUnsupportedCrlVersion, "unsupported crl version")}
	}
	return &ErrUnsupportedCrlVersion{BaseError: newBaseErrorData(NumErrUnsupportedCrlVersion, "unsupported crl version: %d", version)}
}

type ErrInvalidAlgorithmIdentifier struct{ BaseError }

func NewErrInvalidAlgorithmIdentifier() Kerror {
	return &ErrInvalidAlgorithmIdentifier{BaseError: newBaseError(NumErrInvalidAlgorithmIdentifier, "malformed algorithm identifier")}
}

type ErrInconsistentAlgorithms struct{ BaseError }

func NewErrInconsistentAlgorithms() Kerror {
	return &ErrInconsistentAlgorithms{BaseError: newBaseError(NumErrInconsistentAlgorithms, "inner and outer signature algorithm identifiers don't match")}
}

type ErrMalformedCrlNumber struct{ BaseError }

func NewErrMalformedCrlNumber() Kerror {
	return &ErrMalformedCrlNumber{BaseError: newBaseError(NumErrMalformedCrlNumber, "malformed crl number")}
}
