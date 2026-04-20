package pkix

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"

	"github.com/pduveau/gocert/pkerr"
)

// checkSignature verifies that signature is a valid signature over signed from
// a crypto.PublicKey.
func (algo SignatureAlgorithm) CheckSignature(signed, signature []byte, publicKey crypto.PublicKey, allowSHA1 bool) (err pkerr.Kerror) {
	var hashType crypto.Hash
	var pubKeyAlgo PublicKeyAlgorithm

	if details := GetSignatureAlgorithmDetailsFromAlgo(algo); details != nil {
		hashType = details.Hash
		pubKeyAlgo = details.PubKeyAlgo
	}

	switch hashType {
	case crypto.Hash(0):
		if pubKeyAlgo != Ed25519 {
			return pkerr.NewErrUnsupportedAlgorithm("algorithm unimplemented")
		}
	case crypto.MD5:
		return pkerr.NewErrInsecureAlgorithm(algo.String())
	case crypto.SHA1:
		// SHA-1 signatures are only allowed for CRLs and CSRs.
		if !allowSHA1 {
			return pkerr.NewErrInsecureAlgorithm(algo.String())
		}
		fallthrough
	default:
		if !hashType.Available() {
			return pkerr.NewErrUnsupportedAlgorithm()
		}
		h := hashType.New()
		h.Write(signed)
		signed = h.Sum(nil)
	}

	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		if pubKeyAlgo != RSA {
			return pkerr.NewErrSignaturePublicKeyAlgoMismatch(pubKeyAlgo.String(), pub)
		}
		var errNative error
		if algo.IsRSAPSS() {
			errNative = rsa.VerifyPSS(pub, hashType, signed, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		} else {
			errNative = rsa.VerifyPKCS1v15(pub, hashType, signed, signature)
		}
		if errNative == nil {
			return nil
		}
		return pkerr.NewErrNative(errNative)
	case *ecdsa.PublicKey:
		if pubKeyAlgo != ECDSA {
			return pkerr.NewErrSignaturePublicKeyAlgoMismatch(pubKeyAlgo.String(), pub)
		}
		if !ecdsa.VerifyASN1(pub, signed, signature) {
			return pkerr.NewErrECDSAVerificationFailure("ECDSA")
		}
		return
	case ed25519.PublicKey:
		if pubKeyAlgo != Ed25519 {
			return pkerr.NewErrSignaturePublicKeyAlgoMismatch(pubKeyAlgo.String(), pub)
		}
		if !ed25519.Verify(pub, signed, signature) {
			return pkerr.NewErrECDSAVerificationFailure("Ed25519")
		}
		return
	}
	return pkerr.NewErrUnsupportedAlgorithm()
}

func (sigAlg SignatureAlgorithm) Sign(data []byte, key crypto.Signer) ([]byte, pkerr.Kerror) {
	hashFunc := sigAlg.HashFunc()

	var signerOpts crypto.SignerOpts = hashFunc
	if sigAlg.IsRSAPSS() {
		signerOpts = &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       hashFunc,
		}
	}

	signature, err := crypto.SignMessage(key, rand.Reader, data, signerOpts)
	if err != nil {
		return nil, pkerr.NewErrNative(err)
	}

	// Check the signature to ensure the crypto.Signer behaved correctly.
	if err := sigAlg.CheckSignature(data, signature, key.Public(), true); err != nil {
		return nil, pkerr.NewErrInvalidSignature(err.Error())
	}

	return signature, nil
}

// signingParamsForKey returns the signature algorithm and its Algorithm
// Identifier to use for signing, based on the key type. If sigAlgo is not zero
// then it overrides the default.
func (sigAlgo SignatureAlgorithm) SigningParamsForKey(key crypto.Signer) (SignatureAlgorithm, AlgorithmIdentifier, pkerr.Kerror) {
	var ai AlgorithmIdentifier
	var pubType PublicKeyAlgorithm
	var defaultAlgo SignatureAlgorithm

	if key == nil {
		return 0, ai, pkerr.NewErrUnsetKey()
	}

	switch pub := key.Public().(type) {
	case *rsa.PublicKey:
		pubType = RSA
		defaultAlgo = RSAWithSHA256

	case *ecdsa.PublicKey:
		pubType = ECDSA
		switch pub.Curve {
		case elliptic.P224(), elliptic.P256():
			defaultAlgo = ECDSAWithSHA256
		case elliptic.P384():
			defaultAlgo = ECDSAWithSHA384
		case elliptic.P521():
			defaultAlgo = ECDSAWithSHA512
		default:
			return 0, ai, pkerr.NewErrUnsupporteEllipticCurve()
		}

	case ed25519.PublicKey:
		pubType = Ed25519
		defaultAlgo = PureEd25519

	default:
		return 0, ai, pkerr.NewErrRSAECDSAED25519()
	}

	if sigAlgo == 0 {
		sigAlgo = defaultAlgo
	}

	details, err := GetSignatureAlgorithmDetailsFromAlgoAndPubKeyType(sigAlgo, pubType)
	if err != nil {
		return 0, ai, err
	}
	if details != nil {
		return sigAlgo, AlgorithmIdentifier{
			Algorithm:  details.Oid,
			Parameters: details.Params,
		}, nil
	}

	return 0, ai, pkerr.NewErrUnknownSignatureAlgorithm()
}
