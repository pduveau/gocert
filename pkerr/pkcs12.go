package pkerr

type ErrCharUnsupportedInUCS2 struct{ BaseError }

func NewErrCharUnsupportedInUCS2() Kerror {
	return &ErrCharUnsupportedInUCS2{BaseError: newBaseError(NumErrCharUnsupportedInUCS2, "string contains characters that cannot be encoded in UCS-2")}
}

type ErrOddLengthBMPString struct{ BaseError }

func NewErrOddLengthBMPString() Kerror {
	return &ErrOddLengthBMPString{BaseError: newBaseError(NumErrOddLengthBMPString, "odd-length BMP string")}
}

type ErrIncorrectPassword struct{ BaseError }

func NewErrIncorrectPassword() Kerror {
	return &ErrIncorrectPassword{BaseError: newBaseError(NumErrIncorrectPassword, "incorrect decryption password")}
}

type ErrDecodingCertBag struct{ BaseError }

func NewErrDecodingCertBag(v Kerror) Kerror {
	return &ErrDecodingCertBag{BaseError: newBaseErrorData(NumErrDecodingCertBag, "error decoding cert bag: %v", v)}
}

type ErrEncodingCertBag struct{ BaseError }

func NewErrEncodingCertBag(v Kerror) Kerror {
	return &ErrEncodingCertBag{BaseError: newBaseErrorData(NumErrEncodingCertBag, "error encoding cert bag: %v", v)}
}

type ErrOnlyCertificateInCertBag struct{ BaseError }

func NewErrOnlyCertificateInCertBag() Kerror {
	return &ErrOnlyCertificateInCertBag{BaseError: newBaseError(NumErrOnlyCertificateInCertBag, "only X509 certificates are supported in cert bags")}
}

type ErrMacDigestUnsupportedAlgorithm struct{ BaseError }

func NewErrMacDigestUnsupportedAlgorithm(detail any) Kerror {
	return &ErrMacDigestUnsupportedAlgorithm{BaseError: newBaseErrorData(NumErrMacDigestUnsupportedAlgorithm, "MAC digest algorithm not supported: %v", detail)}
}

type ErrOnlyOneCertificateInCertBag struct{ BaseError }

func NewErrOnlyOneCertificateInCertBag() Kerror {
	return &ErrOnlyOneCertificateInCertBag{BaseError: newBaseError(NumErrOnlyOneCertificateInCertBag, "expected exactly one certificate in the certBag")}
}

type ErrOnlyTwoSafeBags struct{ BaseError }

func NewErrOnlyTwoSafeBags() Kerror {
	return &ErrOnlyTwoSafeBags{BaseError: newBaseError(NumErrOnlyTwoSafeBags, "expected exactly two safe bags in the PFX PDU")}
}

type ErrExactlyOneKeyExpected struct{ BaseError }

func NewErrExactlyOneKeyExpected() Kerror {
	return &ErrExactlyOneKeyExpected{BaseError: newBaseError(NumErrExactlyOneKeyExpected, "expected exactly one key bag")}
}

type ErrCertificateMissing struct{ BaseError }

func NewErrCertificateMissing() Kerror {
	return &ErrCertificateMissing{BaseError: newBaseError(NumErrCertificateMissing, "certificate missing")}
}

type ErrKeyMissing struct{ BaseError }

func NewErrKeyMissing() Kerror {
	return &ErrKeyMissing{BaseError: newBaseError(NumErrKeyMissing, "key missing")}
}

type ErrOnlyTrustedCertificateInTrustStore struct{ BaseError }

func NewErrOnlyTrustedCertificateInTrustStore() Kerror {
	return &ErrOnlyTrustedCertificateInTrustStore{BaseError: newBaseError(NumErrOnlyTrustedCertificateInTrustStore, "trust store contains a certificate that is not marked as trusted")}
}

type ErrReadingP12Data struct{ BaseError }

func NewErrReadingP12Data(err error) Kerror {
	return &ErrReadingP12Data{BaseError: newBaseErrorData(NumErrReadingP12Data, "error reading P12 data: %v", err)}
}

type ErrOnlyV3PDU struct{ BaseError }

func NewErrOnlyV3PDU() Kerror {
	return &ErrOnlyV3PDU{BaseError: newBaseError(NumErrOnlyV3PDU, "can only decode v3 PFX PDU's")}
}

type ErrOnlyPasswordPFX struct{ BaseError }

func NewErrOnlyPasswordPFX() Kerror {
	return &ErrOnlyPasswordPFX{BaseError: newBaseError(NumErrOnlyPasswordPFX, "only password-protected PFX is implemented")}
}

type ErrNoMACinData struct{ BaseError }

func NewErrNoMACinData() Kerror {
	return &ErrNoMACinData{BaseError: newBaseError(NumErrNoMACinData, "no MAC in data")}
}

type ErrExpectedExactlyNItems struct{ BaseError }

func NewErrExpectedExactlyNItems(val ...any) Kerror {
	return &ErrExpectedExactlyNItems{BaseError: newBaseErrorData(NumErrExpectedExactlyNItems, "expected exactly %d items in the authenticated safe, but this file has %d", val...)}
}

type ErrExpectedBetweenNandMItems struct{ BaseError }

func NewErrExpectedBetweenNandMItems(val ...any) Kerror {
	return &ErrExpectedBetweenNandMItems{BaseError: newBaseErrorData(NumErrExpectedBetweenNandMItems, "expected between %d and %d items in the authenticated safe, but this file has %d", val...)}
}

type ErrOnlyVersion0 struct{ BaseError }

func NewErrOnlyVersion0() Kerror {
	return &ErrOnlyVersion0{BaseError: newBaseError(NumErrOnlyVersion0, "only version 0 of EncryptedData is supported")}
}

type ErrOnlyDataAndEcryptedDataSupported struct{ BaseError }

func NewErrOnlyDataAndEcryptedDataSupported() Kerror {
	return &ErrOnlyDataAndEcryptedDataSupported{BaseError: newBaseError(NumErrOnlyDataAndEcryptedDataSupported, "only data and encryptedData content types are supported in authenticated safe")}
}

type ErrWritingP12Data struct{ BaseError }

func NewErrWritingP12Data(err Kerror) Kerror {
	return &ErrWritingP12Data{BaseError: newBaseErrorData(NumErrWritingP12Data, "error writing P12 data: %v", err)}
}
