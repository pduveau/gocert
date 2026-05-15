//go:build darwin

package pkerr

type ErrOSStatus struct{ BaseError }

func NewErrOSStatus(call string, status int32) Kerror {
	return &ErrOSStatus{BaseError: NewBaseErrorData(NumErrOSStatus, "%s error: %d", call, status)}
}

type ErrMacOSInvalidCertificate struct{ BaseError }

func NewErrMacOSInvalidCertificate() Kerror {
	return &ErrMacOSInvalidCertificate{BaseError: NewBaseError(NumErrMacOSInvalidCertificate, "SecCertificateCreateWithData: invalid certificate")}
}

type ErrMacOSGeneric struct{ BaseError }

func NewErrMacOSGeneric(e string) Kerror {
	return &ErrMacOSGeneric{BaseError: NewBaseErrorData(NumErrMacOSGeneric, "%s", e)}
}
