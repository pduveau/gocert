package pkerr

// ErrCannotDecryptData tells you when our quick dev assumptions have failed
type ErrCannotDecryptData struct{ BaseError }

func NewErrCannotDecryptData() Kerror {
	return &ErrCannotDecryptData{BaseError: NewBaseError(NumErrCannotDecryptData, "cannot decrypt data: only RSA, DES, TripleDES, AES-256-CBC and AES-128-GCM supported")}
}

// ErrNotEncryptedContent is returned when attempting to Decrypt data that is not encrypted data
type ErrNotEncryptedContent struct{ BaseError }

func NewErrNotEncryptedContent() Kerror {
	return &ErrNotEncryptedContent{BaseError: NewBaseError(NumErrNotEncryptedContent, "content data is a decryptable data type")}
}

// ErrUnsupportedContentType is returned when a PKCS7 content is not supported.
type ErrUnsupportedContentType struct{ BaseError }

func NewErrUnsupportedContentType() Kerror {
	return &ErrUnsupportedContentType{BaseError: NewBaseError(NumErrUnsupportedContentType, "cannot parse data: unimplemented content type")}
}

type ErrEmptyInputData struct{ BaseError }

func NewErrEmptyInputData() Kerror {
	return &ErrEmptyInputData{BaseError: NewBaseError(NumErrEmptyInputData, "input data is empty")}
}

type ErrParsingBER struct{ BaseError }

func NewErrParsingBER() Kerror {
	return &ErrParsingBER{BaseError: NewBaseError(NumErrParsingBER, "error parsing BER")}
}

type ErrNoEnvelopForCertificate struct{ BaseError }

func NewErrNoEnvelopForCertificate() Kerror {
	return &ErrNoEnvelopForCertificate{BaseError: NewBaseError(NumErrNoEnvelopForCertificate, "no enveloped recipient for provided certificate")}
}

type ErrDecryptableDataType struct{ BaseError }

func NewErrDecryptableDataType() Kerror {
	return &ErrDecryptableDataType{BaseError: NewBaseError(NumErrDecryptableDataType, "content data is a decryptable data type")}
}

type ErrInvalidAlgorithmParams struct{ BaseError }

func NewErrInvalidAlgorithmParams() Kerror {
	return &ErrInvalidAlgorithmParams{BaseError: NewBaseError(NumErrInvalidAlgorithmParams, "invalid algorithm parameters")}
}

type ErrNoPSK struct{ BaseError }

func NewErrNoPSK() Kerror {
	return &ErrNoPSK{BaseError: NewBaseError(NumErrNoPSK, "cannot encrypt content: PSK not provided")}
}

type ErrInvalidContentEncryptionAlgorithm struct{ BaseError }

func NewErrInvalidContentEncryptionAlgorithm(enc string, cont string) Kerror {
	return &ErrInvalidContentEncryptionAlgorithm{BaseError: NewBaseErrorData(NumErrInvalidContentEncryptionAlgorithm, "invalid ContentEncryptionAlgorithm in %s: %s", enc, cont)}
}

type ErrNoSignerInfo struct{ BaseError }

func NewErrNoSignerInfo(id int) Kerror {
	return &ErrNoSignerInfo{BaseError: NewBaseErrorData(NumErrNoSignerInfo, "no signer information found for ID %d", id)}
}

type ErrPrivateKeyNotASigner struct{ BaseError }

func NewErrPrivateKeyNotASigner() Kerror {
	return &ErrPrivateKeyNotASigner{BaseError: NewBaseError(NumErrPrivateKeyNotASigner, "private key does not implement crypto.Signer")}
}

type ErrMsgWithoutSigners struct{ BaseError }

func NewErrMsgWithoutSigners() Kerror {
	return &ErrMsgWithoutSigners{BaseError: NewBaseError(NumErrMsgWithoutSigners, "message/payload has no signers")}
}

type ErrNoCertificateForSigner struct{ BaseError }

func NewErrNoCertificateForSigner() Kerror {
	return &ErrNoCertificateForSigner{BaseError: NewBaseError(NumErrNoCertificateForSigner, "no certificate for signer")}
}

type ErrMissingAttributType struct{ BaseError }

func NewErrMissingAttributType() Kerror {
	return &ErrMissingAttributType{BaseError: NewBaseError(NumErrMissingAttributType, "attribute type not in attributes")}
}

type ErrMessageDigestMismatch struct{ BaseError }

func NewErrMessageDigestMismatch() Kerror {
	return &ErrMessageDigestMismatch{BaseError: NewBaseError(NumErrMessageDigestMismatch, "message digest mismatch")}
}

type ErrNoParentToVerify struct{ BaseError }

func NewErrNoParentToVerify(v any) Kerror {
	return &ErrNoParentToVerify{BaseError: NewBaseErrorData(NumErrNoParentToVerify, "zero parents provided to verify the signature of certificate %q", v)}
}

type ErrInvalidSignatureByParent struct{ BaseError }

func NewErrInvalidSignatureByParent(v any) Kerror {
	return &ErrInvalidSignatureByParent{BaseError: NewBaseErrorData(NumErrInvalidSignatureByParent, "certificate signature from parent is invalid: %v", v)}
}

type ErrSigningTimeOutOfValidity struct{ BaseError }

func NewErrSigningTimeOutOfValidity(v ...any) Kerror {
	return &ErrSigningTimeOutOfValidity{BaseError: NewBaseErrorData(NumErrSigningTimeOutOfValidity, "signing time %q is outside of certificate validity %q to %q", v...)}
}

type ErrChainVerify struct{ BaseError }

func NewErrChainVerify(v any) Kerror {
	return &ErrChainVerify{BaseError: NewBaseErrorData(NumErrChainVerify, "failed to verify certificate chain: %v", v)}
}

type ErrMsgHasNoSignedContent struct{ BaseError }

func NewErrMsgHasNoSignedContent() Kerror {
	return &ErrMsgHasNoSignedContent{BaseError: NewBaseError(NumErrMsgHasNoSignedContent, "payload is not signedData content")}
}

type ErrNoSignerInformationFound struct{ BaseError }

func NewErrNoSignerInformationFound(val ...any) Kerror {
	return &ErrNoSignerInformationFound{BaseError: NewBaseErrorData(NumErrNoSignerInformationFound, "no signer information found for ID %d", val...)}
}

type ErrNoCallBackDefined struct{ BaseError }

func NewErrNoCallBackDefined() Kerror {
	return &ErrNoCallBackDefined{BaseError: NewBaseError(NumErrNoCallBackDefined, "no callback defined")}
}
