//go:build darwin

package pkerr

type ErrOSStatus struct{ BaseError }

func NewErrOSStatus(call string, status int32) Pkerror {
	return &ErrOSStatus{BaseError: NewBaseErrorData(NumErrOSStatus, "%s error: %d", call, status)}
}

type ErrMacOSInvalidCertificate struct{ BaseError }

func NewErrMacOSInvalidCertificate() Pkerror {
	return &ErrMacOSInvalidCertificate{BaseError: NewBaseError(NumErrMacOSInvalidCertificate, "SecCertificateCreateWithData: invalid certificate")}
}

type ErrMacOSGeneric struct{ BaseError }

func NewErrMacOSGeneric(e string) Pkerror {
	return &ErrMacOSGeneric{BaseError: NewBaseErrorData(NumErrMacOSGeneric, "%s", e)}
}
