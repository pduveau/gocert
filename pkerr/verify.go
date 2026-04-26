package pkerr

type ErrInvalidHostname struct{ BaseError }

func NewErrInvalidHostname(reason ErrorNumeric, detail ...any) Kerror {
	switch reason {
	case NumErrHostnameLegacyCNField:
		return &ErrInvalidHostname{BaseError: NewBaseError(NumErrHostnameLegacyCNField, "certificate relies on legacy Common Name field, use SANs instead")}
	case NumErrHostnameDoesNotContainIPSAN:
		return &ErrInvalidHostname{BaseError: NewBaseErrorData(NumErrHostnameDoesNotContainIPSAN, "cannot validate certificate for %s because it doesn't contain any IP SANs", detail...)}
	case NumErrHostnameNoneIPSANMatched:
		return &ErrInvalidHostname{BaseError: NewBaseErrorData(NumErrHostnameNoneIPSANMatched, "certificate is valid for %d IP SANs, but none matched %s", detail...)}
	case NumErrHostnameNoneDNSSANMatched:
		return &ErrInvalidHostname{BaseError: NewBaseErrorData(NumErrHostnameNoneDNSSANMatched, "certificate is valid for %d names, but none matched %s", detail...)}
	case NumErrHostnameCertificateNotValidForAnyNames:
		return &ErrInvalidHostname{BaseError: NewBaseErrorData(NumErrHostnameCertificateNotValidForAnyNames, "certificate is not valid for any names, but wanted to match %s", detail...)}
	case NumErrHostnameCertificateValidButNotForName:
		return &ErrInvalidHostname{BaseError: NewBaseErrorData(NumErrHostnameCertificateValidButNotForName, "certificate is valid for %s, not %s", detail...)}
	}
	return &ErrInvalidHostname{BaseError: NewBaseError(reason, "unknown error")}
}

type ErrUnknownAuthority struct{ BaseError }

func NewErrUnknownAuthority(hint ...any) Kerror {
	if len(hint) == 0 {
		return &ErrUnknownAuthority{BaseError: NewBaseError(NumErrUnknownAuthority, "certificate signed by unknown authority")}
	}
	return &ErrUnknownAuthority{BaseError: NewBaseErrorData(NumErrUnknownAuthority, "certificate signed by unknown authority (possibly because of %q while trying to verify candidate authority certificate %q)", hint...)}
}

type ErrSignatureCheckReachDeepLimit struct{ BaseError }

func NewErrSignatureCheckReachDeepLimit() Kerror {
	return &ErrSignatureCheckReachDeepLimit{BaseError: NewBaseError(NumErrSignatureCheckReachDeepLimit, "signature check attempts limit reached while verifying certificate chain")}
}

type ErrCertficateNotParsed struct{ BaseError }

func NewErrCertficateNotParsed() Kerror {
	return &ErrCertficateNotParsed{BaseError: NewBaseError(NumErrCertficateNotParsed, "missing ASN.1 contents; use ParseCertificate")}
}

type ErrFetchingIntermediaries struct{ BaseError }

func NewErrFetchingIntermediaries(val error) Kerror {
	return &ErrFetchingIntermediaries{BaseError: NewBaseErrorData(NumErrFetchingIntermediaries, "error fetching intermediate: %w", val)}
}

type ErrEmptyChainWhileAppending struct{ BaseError }

func NewErrEmptyChainWhileAppending() Kerror {
	return &ErrEmptyChainWhileAppending{BaseError: NewBaseError(NumErrEmptyChainWhileAppending, "empty chain when appending CA cert")}
}

type ErrBad struct{ BaseError }

func NewErrBad() Kerror {
	return &ErrBad{BaseError: NewBaseError(NumErrBad, "bad")}
}
