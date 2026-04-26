package pkerr

type ErrEncryptionParams struct{ BaseError }

func NewErrEncryptionParams() Kerror {
	return &ErrEncryptionParams{BaseError: NewBaseError(NumErrEncryptionParams, "encryption algorithm parameters are incorrect")}
}

type ErrEncryptionBocklen struct{ BaseError }

func NewErrEncryptionBocklen(d int) Kerror {
	return &ErrEncryptionBocklen{BaseError: NewBaseErrorData(NumErrEncryptionBocklen, "encryption invalid bock len %d", d)}
}

type ErrEncryptionDatalen struct{ BaseError }

func NewErrEncryptionDatalen(d int) Kerror {
	return &ErrEncryptionDatalen{BaseError: NewBaseErrorData(NumErrEncryptionDatalen, "encryption invalid data len %d", d)}
}

type ErrEncryptionData struct{ BaseError }

func NewErrEncryptionData() Kerror {
	return &ErrEncryptionData{BaseError: NewBaseError(NumErrEncryptionData, "encryption invalid data")}
}

type ErrEncryptionPadding struct{ BaseError }

func NewErrEncryptionPadding() Kerror {
	return &ErrEncryptionPadding{BaseError: NewBaseError(NumErrEncryptionPadding, "encryption invalid padding")}
}

type ErrFailToParsePrivateKeyGotoPKCS1 struct{ BaseError }

func NewErrFailToParsePrivateKeyGotoPKCS1() Kerror {
	return &ErrFailToParsePrivateKeyGotoPKCS1{BaseError: NewBaseError(NumErrFailToParsePrivateKeyGotoPKCS1, "failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)")}
}

type ErrFailToParsePublicKeyGotoPKCS1 struct{ BaseError }

func NewErrFailToParsePublicKeyGotoPKCS1() Kerror {
	return &ErrFailToParsePublicKeyGotoPKCS1{BaseError: NewBaseError(NumErrFailToParsePublicKeyGotoPKCS1, "failed to parse public key (use ParsePKCS1PublicKey instead for this key format)")}
}

type ErrFailToParsePrivateKeyGotoPKCS8 struct{ BaseError }

func NewErrFailToParsePrivateKeyGotoPKCS8() Kerror {
	return &ErrFailToParsePrivateKeyGotoPKCS8{BaseError: NewBaseError(NumErrFailToParsePrivateKeyGotoPKCS8, "failed to parse private key (use ParsePKCS8PrivateKey instead for this key format)")}
}

type ErrFailToParsePrivateKeyGotoECP struct{ BaseError }

func NewErrFailToParsePrivateKeyGotoECP() Kerror {
	return &ErrFailToParsePrivateKeyGotoECP{BaseError: NewBaseError(NumErrFailToParsePrivateKeyGotoECP, "failed to parse private key (use ParseECPrivateKey instead for this key format)")}
}

type ErrFailToParsePrivateKeyGotoPKIX struct{ BaseError }

func NewErrFailToParsePrivateKeyGotoPKIX() Kerror {
	return &ErrFailToParsePrivateKeyGotoPKIX{BaseError: NewBaseError(NumErrFailToParsePrivateKeyGotoPKIX, "failed to parse private key (use ParsePKIXPrivateKey instead for this key format)")}
}

type ErrFailToParsePublicKeyGotoPKIX struct{ BaseError }

func NewErrFailToParsePublicKeyGotoPKIX() Kerror {
	return &ErrFailToParsePublicKeyGotoPKIX{BaseError: NewBaseError(NumErrFailToParsePublicKeyGotoPKIX, "failed to parse public key (use ParsePKIXPublicKey instead for this key format)")}
}

type ErrFailToParsePrivateKey struct{ BaseError }

func NewErrFailToParseECPrivateKey(err error) Kerror {
	return &ErrFailToParsePrivateKey{BaseError: NewBaseErrorData(NumErrFailToParsePrivateKey, "failed to parse EC private key %e", err.Error())}
}

type ErrUnknownPrivateKeyVersion struct{ BaseError }

func NewErrUnknownPrivateKeyVersion(version int) Kerror {
	return &ErrUnknownPrivateKeyVersion{BaseError: NewBaseErrorData(NumErrUnknownPrivateKeyVersion, "unknown private key version %d", version)}
}

type ErrUnknownEC struct{ BaseError }

func NewErrUnknownEC() Kerror {
	return &ErrUnknownEC{BaseError: NewBaseError(NumErrUnknownEC, "unknown elliptic curve")}
}

type ErrUnsupportedEC struct{ BaseError }

func NewErrUnsupportedEC() Kerror {
	return &ErrUnsupportedEC{BaseError: NewBaseError(NumErrUnsupportedEC, "unsupported elliptic curve")}
}

type ErrInvalidKeylen struct{ BaseError }

func NewErrInvalidKeylen() Kerror {
	return &ErrInvalidKeylen{BaseError: NewBaseError(NumErrInvalidKeylen, "invalid private key length")}
}

type ErrRSAMissingParams struct{ BaseError }

func NewErrRSAMissingParams() Kerror {
	return &ErrRSAMissingParams{BaseError: NewBaseError(NumErrRSAMissingParams, "RSA key missing NULL parameters")}
}

type ErrRSAInvalidPublicKey struct{ BaseError }

func NewErrRSAInvalidPublicKey() Kerror {
	return &ErrRSAInvalidPublicKey{BaseError: NewBaseError(NumErrRSAInvalidPublicKey, "invalid RSA public key")}
}

type ErrRSAInvalidModulus struct{ BaseError }

func NewErrRSAInvalidModulus() Kerror {
	return &ErrRSAInvalidModulus{BaseError: NewBaseError(NumErrRSAInvalidModulus, "invalid RSA modulus")}
}

type ErrRSAInvalidPublicExponent struct{ BaseError }

func NewErrRSAInvalidPublicExponent() Kerror {
	return &ErrRSAInvalidPublicExponent{BaseError: NewBaseError(NumErrRSAInvalidPublicExponent, "invalid RSA public exponent")}
}

type ErrInvalidECDSAParams struct{ BaseError }

func NewErrInvalidECDSAParams() Kerror {
	return &ErrInvalidECDSAParams{BaseError: NewBaseError(NumErrInvalidECDSAParams, "invalid ECDSA parameters")}
}

type ErrEd25519Keylen struct{ BaseError }

func NewErrEd25519Keylen() Kerror {
	return &ErrEd25519Keylen{BaseError: NewBaseError(NumErrEd25519Keylen, "wrong Ed25519 public key size")}
}

type ErrIllegalX25519Params struct{ BaseError }

func NewErrIllegalX25519Params() Kerror {
	return &ErrIllegalX25519Params{BaseError: NewBaseError(NumErrIllegalX25519Params, "X25519 key encoded with illegal parameters")}
}

type ErrDeprecatedAlgorithm struct{ BaseError }

func NewErrDeprecatedAlgorithm() Kerror {
	return &ErrDeprecatedAlgorithm{BaseError: NewBaseError(NumErrDeprecatedAlgorithm, "deprecated algorithm")}
}

type ErrUnknownPubKeyAlgorithm struct{ BaseError }

func NewErrUnknownPubKeyAlgorithm() Kerror {
	return &ErrUnknownPubKeyAlgorithm{BaseError: NewBaseError(NumErrUnknownPubKeyAlgorithm, "unknown public key algorithm")}
}

type ErrUnsupportedPublicKeyType struct{ BaseError }

func NewErrUnsupportedPublicKeyType(t any) Kerror {
	return &ErrUnsupportedPublicKeyType{BaseError: NewBaseErrorData(NumErrUnsupportedPublicKeyType, "unsupported public key type: %T", t)}
}

type ErrGeneralizedTime struct{ BaseError }

func NewErrGeneralizedTime(t any) Kerror {
	return &ErrGeneralizedTime{BaseError: NewBaseErrorData(NumErrGeneralizedTime, "cannot represent %v as a GeneralizedTime", t)}
}

type ErrUTCTime struct{ BaseError }

func NewErrUTCTime(t any) Kerror {
	return &ErrUTCTime{BaseError: NewBaseErrorData(NumErrUTCTime, "cannot represent %v as a UTCTime", t)}
}

type ErrHighTagValue struct{ BaseError }

func NewErrHighTagValue(tag any) Kerror {
	return &ErrHighTagValue{BaseError: NewBaseErrorData(NumErrHighTagValue, "high-tag number identifier octets not supported: 0x%x", tag)}
}

type ErrBuilderASN1ChildTooLong struct{ BaseError }

func NewErrBuilderASN1ChildTooLong() Kerror {
	return &ErrBuilderASN1ChildTooLong{BaseError: NewBaseError(NumErrBuilderASN1ChildTooLong, "pending ASN.1 child too long")}
}

type ErrBuilderASN1ChildExceed struct{ BaseError }

func NewErrBuilderASN1ChildExceed(lengths ...any) Kerror {
	return &ErrBuilderASN1ChildExceed{BaseError: NewBaseErrorData(NumErrBuilderASN1ChildExceed, "pending ASN.1 child length %d exceeds %d-byte length prefix", lengths...)}
}

type ErrBuildASN1Overflow struct{ BaseError }

func NewErrBuildASN1Overflow() Kerror {
	return &ErrBuildASN1Overflow{BaseError: NewBaseError(NumErrBuildASN1Overflow, "length overflow")}
}

type ErrBuildASN1ExceedsBuffer struct{ BaseError }

func NewErrBuildASN1ExceedsBuffer() Kerror {
	return &ErrBuildASN1ExceedsBuffer{BaseError: NewBaseError(NumErrBuildASN1ExceedsBuffer, "Builder is exceeding its fixed-size buffer")}
}

type ErrUnsupportedStringType struct{ BaseError }

func NewErrUnsupportedStringType(tag any) Kerror {
	return &ErrUnsupportedStringType{BaseError: NewBaseErrorData(NumErrUnsupportedStringType, "unsupported string type: %v", tag)}
}

type ErrInvalidRDNSequence struct{ BaseError }

func NewErrInvalidRDNSequence(sub ...string) Kerror {
	if len(sub) > 0 {
		return &ErrInvalidRDNSequence{BaseError: NewBaseErrorData(NumErrInvalidRDNSequence, "invalid RDNSequence: invalid attribute%s", sub[0])}
	}
	return &ErrInvalidRDNSequence{BaseError: NewBaseError(NumErrInvalidRDNSequence, "invalid RDNSequence")}
}

type ErrMalformedGeneralizedTime struct{ BaseError }

func NewErrMalformedGeneralizedTime() Kerror {
	return &ErrMalformedGeneralizedTime{BaseError: NewBaseError(NumErrMalformedGeneralizedTime, "malformed GeneralizedTime")}
}

type ErrMalformedUTCTime struct{ BaseError }

func NewErrMalformedUTCTime() Kerror {
	return &ErrMalformedUTCTime{BaseError: NewBaseError(NumErrMalformedUTCTime, "malformed UTCTime")}
}

type ErrMalformedTime struct{ BaseError }

func NewErrMalformedTime() Kerror {
	return &ErrMalformedTime{BaseError: NewBaseError(NumErrMalformedTime, "malformed time format")}
}
