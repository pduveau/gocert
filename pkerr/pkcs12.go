package pkerr

type ErrCharUnsupportedInUCS2 struct{ BaseError }

func NewErrCharUnsupportedInUCS2() Kerror {
	return &ErrCharUnsupportedInUCS2{BaseError: NewBaseError(NumErrCharUnsupportedInUCS2, "string contains characters that cannot be encoded in UCS-2")}
}

type ErrOddLengthBMPString struct{ BaseError }

func NewErrOddLengthBMPString() Kerror {
	return &ErrOddLengthBMPString{BaseError: NewBaseError(NumErrOddLengthBMPString, "odd-length BMP string")}
}

type ErrIncorrectPassword struct{ BaseError }

func NewErrIncorrectPassword() Kerror {
	return &ErrIncorrectPassword{BaseError: NewBaseError(NumErrIncorrectPassword, "incorrect decryption password")}
}

type ErrDecodingCertBag struct{ BaseError }

func NewErrDecodingCertBag(v Kerror) Kerror {
	return &ErrDecodingCertBag{BaseError: NewBaseErrorData(NumErrDecodingCertBag, "error decoding cert bag: %v", v)}
}

type ErrEncodingCertBag struct{ BaseError }

func NewErrEncodingCertBag(v Kerror) Kerror {
	return &ErrEncodingCertBag{BaseError: NewBaseErrorData(NumErrEncodingCertBag, "error encoding cert bag: %v", v)}
}

type ErrOnlyCertificateInCertBag struct{ BaseError }

func NewErrOnlyCertificateInCertBag() Kerror {
	return &ErrOnlyCertificateInCertBag{BaseError: NewBaseError(NumErrOnlyCertificateInCertBag, "only X509 certificates are supported in cert bags")}
}

type ErrMacDigestUnsupportedAlgorithm struct{ BaseError }

func NewErrMacDigestUnsupportedAlgorithm(detail any) Kerror {
	return &ErrMacDigestUnsupportedAlgorithm{BaseError: NewBaseErrorData(NumErrMacDigestUnsupportedAlgorithm, "MAC digest algorithm not supported: %v", detail)}
}

type ErrOnlyOneCertificateInCertBag struct{ BaseError }

func NewErrOnlyOneCertificateInCertBag() Kerror {
	return &ErrOnlyOneCertificateInCertBag{BaseError: NewBaseError(NumErrOnlyOneCertificateInCertBag, "expected exactly one certificate in the certBag")}
}

type ErrOnlyTwoSafeBags struct{ BaseError }

func NewErrOnlyTwoSafeBags() Kerror {
	return &ErrOnlyTwoSafeBags{BaseError: NewBaseError(NumErrOnlyTwoSafeBags, "expected exactly two safe bags in the PFX PDU")}
}

type ErrExactlyOneKeyExpected struct{ BaseError }

func NewErrExactlyOneKeyExpected() Kerror {
	return &ErrExactlyOneKeyExpected{BaseError: NewBaseError(NumErrExactlyOneKeyExpected, "expected exactly one key bag")}
}

type ErrCertificateMissing struct{ BaseError }

func NewErrCertificateMissing() Kerror {
	return &ErrCertificateMissing{BaseError: NewBaseError(NumErrCertificateMissing, "certificate missing")}
}

type ErrKeyMissing struct{ BaseError }

func NewErrKeyMissing() Kerror {
	return &ErrKeyMissing{BaseError: NewBaseError(NumErrKeyMissing, "key missing")}
}

type ErrOnlyTrustedCertificateInTrustStore struct{ BaseError }

func NewErrOnlyTrustedCertificateInTrustStore() Kerror {
	return &ErrOnlyTrustedCertificateInTrustStore{BaseError: NewBaseError(NumErrOnlyTrustedCertificateInTrustStore, "trust store contains a certificate that is not marked as trusted")}
}

type ErrReadingP12Data struct{ BaseError }

func NewErrReadingP12Data(err error) Kerror {
	return &ErrReadingP12Data{BaseError: NewBaseErrorData(NumErrReadingP12Data, "error reading P12 data: %v", err)}
}

type ErrOnlyV3PDU struct{ BaseError }

func NewErrOnlyV3PDU() Kerror {
	return &ErrOnlyV3PDU{BaseError: NewBaseError(NumErrOnlyV3PDU, "can only decode v3 PFX PDU's")}
}

type ErrOnlyPasswordPFX struct{ BaseError }

func NewErrOnlyPasswordPFX() Kerror {
	return &ErrOnlyPasswordPFX{BaseError: NewBaseError(NumErrOnlyPasswordPFX, "only password-protected PFX is implemented")}
}

type ErrNoMACinData struct{ BaseError }

func NewErrNoMACinData() Kerror {
	return &ErrNoMACinData{BaseError: NewBaseError(NumErrNoMACinData, "no MAC in data")}
}

type ErrExpectedExactlyNItems struct{ BaseError }

func NewErrExpectedExactlyNItems(val ...any) Kerror {
	return &ErrExpectedExactlyNItems{BaseError: NewBaseErrorData(NumErrExpectedExactlyNItems, "expected exactly %d items in the authenticated safe, but this file has %d", val...)}
}

type ErrExpectedBetweenNandMItems struct{ BaseError }

func NewErrExpectedBetweenNandMItems(val ...any) Kerror {
	return &ErrExpectedBetweenNandMItems{BaseError: NewBaseErrorData(NumErrExpectedBetweenNandMItems, "expected between %d and %d items in the authenticated safe, but this file has %d", val...)}
}

type ErrOnlyVersion0 struct{ BaseError }

func NewErrOnlyVersion0() Kerror {
	return &ErrOnlyVersion0{BaseError: NewBaseError(NumErrOnlyVersion0, "only version 0 of EncryptedData is supported")}
}

type ErrOnlyDataAndEcryptedDataSupported struct{ BaseError }

func NewErrOnlyDataAndEcryptedDataSupported() Kerror {
	return &ErrOnlyDataAndEcryptedDataSupported{BaseError: NewBaseError(NumErrOnlyDataAndEcryptedDataSupported, "only data and encryptedData content types are supported in authenticated safe")}
}

type ErrWritingP12Data struct{ BaseError }

func NewErrWritingP12Data(err Kerror) Kerror {
	return &ErrWritingP12Data{BaseError: NewBaseErrorData(NumErrWritingP12Data, "error writing P12 data: %v", err)}
}
