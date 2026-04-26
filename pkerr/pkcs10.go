package pkerr

type ErrDuplicateExtensionInCertificateRequest struct{ BaseError }

func NewErrDuplicateExtensionInCertificateRequest() Kerror {
	return &ErrDuplicateExtensionInCertificateRequest{BaseError: NewBaseError(NumErrDuplicateExtensionInCertificateRequest, "certificate request contains duplicate requested extensions")}
}

type ErrPrivateKeyIsNotSigner struct{ BaseError }

func NewErrPrivateKeyIsNotSigner() Kerror {
	return &ErrPrivateKeyIsNotSigner{BaseError: NewBaseError(NumErrPrivateKeyIsNotSigner, "private key does not implement crypto.Signer")}
}

type ErrFailtoMarshalExtensions struct{ BaseError }

func NewErrFailtoMarshalExtensions(err Kerror) Kerror {
	return &ErrFailtoMarshalExtensions{BaseError: NewBaseErrorData(NumErrFailtoMarshalExtensions, "failed to serialise extensions attribute: %v", err)}
}
