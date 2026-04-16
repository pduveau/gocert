package pkcs5

import (
	"crypto/rand"
	"fmt"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/pkix"
)

type HmacOID asn1.ObjectIdentifier
type CipherOID asn1.ObjectIdentifier

var (
	OidScrypt      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11}
	OidPKCS5PBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	OidPBES2       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	OidPBMAC1      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}

	// Hmac Algorithms
	OidHMACWithSHA1       = HmacOID{1, 2, 840, 113549, 2, 7}
	OidHMACWithSHA224     = HmacOID{1, 2, 840, 113549, 2, 8}
	OidHMACWithSHA256     = HmacOID{1, 2, 840, 113549, 2, 9}
	OidHMACWithSHA384     = HmacOID{1, 2, 840, 113549, 2, 10}
	OidHMACWithSHA512     = HmacOID{1, 2, 840, 113549, 2, 11}
	OidHMACWithSHA512_224 = HmacOID{1, 2, 840, 113549, 2, 12}
	OidHMACWithSHA512_256 = HmacOID{1, 2, 840, 113549, 2, 13}

	// Encryption Algorithms
	OidAES128CBC = CipherOID{2, 16, 840, 1, 101, 3, 4, 1, 2}
	OidAES192CBC = CipherOID{2, 16, 840, 1, 101, 3, 4, 1, 22}
	OidAES256CBC = CipherOID{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

// DefaultOpts are the default options for encrypting a key if none are given.
// The defaults can be changed by the library user.
func NewDefaultOpts() *Opts {
	return &Opts{
		Cipher:    NewDefaultCipher(),
		KDFParams: NewDefaultKDF(),
		Oid:       OidPBES2,
	}
}

func NewDefaultPBMAC1Opts() *Opts {
	return &Opts{
		Cipher:    NewDefaultPBMAC1Cipher(),
		KDFParams: NewDefaultKDF(),
		Oid:       OidPBMAC1,
	}
}

// Opts contains options for encrypting a PKCS#8 key.
type Opts struct {
	Cipher    Cipher
	KDFParams KDFParams
	SaltSize  int
	Oid       asn1.ObjectIdentifier
}

type pbes2Params struct {
	KeyDerivationFunc pkix.AlgorithmIdentifier
	EncryptionScheme  pkix.AlgorithmIdentifier
}

func ParseKeyDerivationFunc(keyDerivationFunc pkix.AlgorithmIdentifier) (params KDFParams, err error) {
	params, err = NewKDFParams(keyDerivationFunc.Algorithm)
	if err == nil {
		_, err = asn1.Unmarshal(keyDerivationFunc.Parameters.FullBytes, params)
		if err != nil {
			return nil, fmt.Errorf("pkcs8: invalid KDF parameters (%v)", err)
		}
	}
	return
}

func ParseEncryptionScheme(encryptionScheme pkix.AlgorithmIdentifier) (cipher Cipher, iv []byte, err error) {
	cipher, err = NewCipher(CipherOID(encryptionScheme.Algorithm))
	if err == nil {
		if _, err := asn1.Unmarshal(encryptionScheme.Parameters.FullBytes, &iv); err != nil {
			return nil, nil, fmt.Errorf("pkcs8: invalid cipher parameters")
		}
	}
	return
}

func ParsePBES2Params(data []byte) (params *pbes2Params, err error) {
	var rest []byte
	params = &pbes2Params{}
	rest, err = asn1.Unmarshal(data, params)
	if err == nil && len(rest) > 0 {
		err = fmt.Errorf("pkcs8: invalid PBES2 parameters")
	}
	return
}

// ParsePrivateKey parses a DER-encoded PKCS#8 private key.
func ParseEncryptedPKCS5(encryptionAlgorithm pkix.AlgorithmIdentifier, encryptedData []byte, password []byte) ([]byte, KDFParams, error) {
	// No password provided, assume the private key is unencrypted
	if len(password) == 0 {
		return nil, nil, fmt.Errorf("pkcs8: password is required")
	}

	if !encryptionAlgorithm.Algorithm.Equal(OidPBES2) {
		return nil, nil, fmt.Errorf("pkcs8: only PBES2 supported")
	}

	params, err := ParsePBES2Params(encryptionAlgorithm.Parameters.FullBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("pkcs8: invalid PBES2 parameters")
	}

	cipher, iv, err := ParseEncryptionScheme(params.EncryptionScheme)
	if err != nil {
		return nil, nil, err
	}

	kdfParams, err := ParseKeyDerivationFunc(params.KeyDerivationFunc)
	if err != nil {
		return nil, nil, err
	}

	symkey, err := kdfParams.DeriveKey(password, cipher.KeySize())
	if err != nil {
		return nil, nil, err
	}

	decryptedData, err := cipher.Decrypt(symkey, iv, encryptedData)
	if err != nil {
		return nil, nil, err
	}

	return decryptedData, kdfParams, nil
}

func MakePBES2(options ...*Opts) (*pkix.AlgorithmIdentifier, []byte, error) {
	opts := NewDefaultOpts()
	if len(options) > 0 || options[0] != nil {
		opts = options[0]
	}

	iv := make([]byte, opts.Cipher.IVSize())
	_, err := rand.Read(iv)
	if err != nil {
		return nil, nil, err
	}
	err = opts.KDFParams.MakeSalt(opts.SaltSize)
	if err != nil {
		return nil, nil, err
	}
	marshalledParams, err := asn1.Marshal(opts.KDFParams.Param())
	if err != nil {
		return nil, nil, err
	}
	marshalledIV, err := asn1.Marshal(iv)
	if err != nil {
		return nil, nil, err
	}
	encryptionAlgorithmParams := pbes2Params{
		EncryptionScheme: pkix.AlgorithmIdentifier{
			Algorithm:  opts.Cipher.OID(),
			Parameters: asn1.RawValue{FullBytes: marshalledIV},
		},
		KeyDerivationFunc: pkix.AlgorithmIdentifier{
			Algorithm:  opts.KDFParams.OID(),
			Parameters: asn1.RawValue{FullBytes: marshalledParams},
		},
	}
	marshalledEncryptionAlgorithmParams, err := asn1.Marshal(encryptionAlgorithmParams)
	if err != nil {
		return nil, nil, err
	}

	oid := OidPBES2
	if opts.Oid != nil {
		oid = opts.Oid
	}

	return &pkix.AlgorithmIdentifier{
		Algorithm:  oid,
		Parameters: asn1.RawValue{FullBytes: marshalledEncryptionAlgorithmParams},
	}, iv, nil

}

// MarshalPrivateKey encodes a private key into DER-encoded PKCS#8 with the given options.
func MarshalEncryptedPKCS5(data []byte, password []byte, options ...*Opts) (encryptionAlgorithm *pkix.AlgorithmIdentifier, encryptedData []byte, err error) {
	var iv, key []byte
	if len(password) == 0 {
		err = fmt.Errorf("pkcs8: password is required")
		return
	}

	opts := NewDefaultOpts()
	if len(options) > 0 || options[0] != nil {
		opts = options[0]
	}

	encryptionAlgorithm, iv, err = MakePBES2(options...)

	key, err = opts.KDFParams.DeriveKey(password, opts.Cipher.KeySize())
	if err != nil {
		return
	}
	encryptedData, err = opts.Cipher.Encrypt(key, iv, data)

	return
}
