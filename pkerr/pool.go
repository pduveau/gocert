package pkerr

// CertificateInvalidError results when an odd error occurs. Users of this
// library probably want to handle all these errors uniformly.
type ErrInvalidCertificate struct{ BaseError }

func NewErrCertificateInvalid(reason ErrorNumeric, detail ...any) Kerror {
	switch reason {
	case NumErrNotAuthorizedToSign:
		return &ErrInvalidCertificate{BaseError: NewBaseError(reason, "certificate is not authorized to sign other certificates")}
	case NunErrExpired:
		if len(detail) < 3 {
			return &ErrInvalidCertificate{BaseError: NewBaseError(reason, "certificate has expired or is not yet valid")}
		}
		return &ErrInvalidCertificate{BaseError: NewBaseErrorData(reason, "certificate has expired or is not yet valid: current time %s %s %s", detail...)}
	case NunErrCANotAuthorizedForThisName:
		return &ErrInvalidCertificate{BaseError: NewBaseErrorData(reason, "a root or intermediate certificate is not authorized to sign for this name: %s", detail...)}
	case NunErrCANotAuthorizedForExtKeyUsage:
		return &ErrInvalidCertificate{BaseError: NewBaseErrorData(reason, "a root or intermediate certificate is not authorized for an extended key usage: %s", detail...)}
	case NunErrTooManyIntermediates:
		return &ErrInvalidCertificate{BaseError: NewBaseError(reason, "too many intermediates for path length constraint")}
	case NunErrIncompatibleUsage:
		return &ErrInvalidCertificate{BaseError: NewBaseError(reason, "certificate specifies an incompatible key usage")}
	case NunErrNameMismatch:
		return &ErrInvalidCertificate{BaseError: NewBaseError(reason, "issuer name does not match subject from issuing certificate")}
	case NunErrNameConstraintsWithoutSANs:
		return &ErrInvalidCertificate{BaseError: NewBaseError(reason, "issuer has name constraints but leaf doesn't have a SAN extension")}
	case NunErrUnconstrainedName:
		return &ErrInvalidCertificate{BaseError: NewBaseErrorData(reason, "issuer has name constraints but leaf contains unknown or unconstrained name: %s", detail...)}
	case NunErrNoValidChains:
		var s string
		if len(detail) > 0 {
			s, _ = detail[0].(string)
		}
		if s == "" {
			return &ErrInvalidCertificate{BaseError: NewBaseError(reason, "no valid chains built")}
		}
		return &ErrInvalidCertificate{BaseError: NewBaseErrorData(reason, "no valid chains built: %s", s)}
	}
	return &ErrInvalidCertificate{BaseError: NewBaseError(reason, "unknown error")}
}

type ErrInvalidSimpleChain struct{ BaseError }

func NewErrInvalidSimpleChain() Kerror {
	return &ErrInvalidSimpleChain{BaseError: NewBaseError(NumErrInvalidSimpleChain, "invalid simple chain")}
}

type ErrSystemRoots struct{ BaseError }

func NewErrSystemRoots(err error) Kerror {
	return &ErrSystemRoots{BaseError: NewBaseErrorData(NumErrSystemRoots, "failed to load system roots and no roots provided %w", err)}
}

type ErrEmptyChain struct{ BaseError }

func NewErrEmptyChain() Kerror {
	return &ErrEmptyChain{BaseError: NewBaseError(NumErrEmptyChain, "system verifier returned an empty chain")}
}

type ErrInvalidLeafCertificate struct{ BaseError }

func NewErrInvalidLeafCertificate() Kerror {
	return &ErrInvalidLeafCertificate{BaseError: NewBaseError(NumErrInvalidLeafCertificate, "invalid leaf certificate")}
}

type ErrMacOSInternal struct{ BaseError }

func NewErrMacOSInternal() Kerror {
	return &ErrMacOSInternal{BaseError: NewBaseError(NumErrMacOSInternal, "macos certificate verification internal error")}
}
