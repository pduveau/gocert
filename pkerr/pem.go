package pkerr

type ErrNoDeckInfoInBlock struct{ BaseError }

func NewErrNoDeckInfoInBlock() Kerror {
	return &ErrNoDeckInfoInBlock{BaseError: NewBaseError(NumErrNoDeckInfoInBlock, "no DEK-Info header in block")}
}

type ErrUnknownEncryptionMode struct{ BaseError }

func NewErrUnknownEncryptionMode() Kerror {
	return &ErrUnknownEncryptionMode{BaseError: NewBaseError(NumErrUnknownEncryptionMode, "unknown encryption mode")}
}

type ErrIncorrectIVSize struct{ BaseError }

func NewErrIncorrectIVSize() Kerror {
	return &ErrIncorrectIVSize{BaseError: NewBaseError(NumErrIncorrectIVSize, "incorrect IV size")}
}

type ErrEncryptedNotMatchingBlocSizing struct{ BaseError }

func NewErrEncryptedNotMatchingBlocSizing() Kerror {
	return &ErrEncryptedNotMatchingBlocSizing{BaseError: NewBaseError(NumErrEncryptedNotMatchingBlocSizing, "encrypted PEM data is not a multiple of the block size")}
}

type ErrIVGeneration struct{ BaseError }

func NewErrIVGeneration(err any) Kerror {
	return &ErrIVGeneration{BaseError: NewBaseErrorData(NumErrIVGeneration, "cannot generate IV: %v", err)}
}

type ErrFailToParsePEM struct{ BaseError }

func NewErrFailToParsePEM() Kerror {
	return &ErrFailToParsePEM{BaseError: NewBaseError(NumErrFailToParsePEM, "failed to decode PEM")}
}
