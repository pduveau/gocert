package pkcs5

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/pkerr"
	"github.com/pduveau/gocert/pkix"
)

// DefaultOpts are the default options for encrypting a key if none are given.
// The defaults can be changed by the library user.
func NewDefaultOpts() *Opts {
	return &Opts{
		Cipher:    NewDefaultCipher(),
		KDFParams: NewDefaultKDF(),
		Oid:       pkix.OidPBES2,
	}
}

func NewDefaultPBMAC1Opts() *Opts {
	return &Opts{
		Cipher:    NewDefaultPBMAC1Cipher(),
		KDFParams: NewDefaultKDF(),
		Oid:       pkix.OidPBMAC1,
	}
}

// Opts contains options for encrypting a PKCS#8 key.
type Opts struct {
	Cipher    Cipher
	KDFParams KDFParams
	SaltSize  int
	Oid       asn1.ObjectIdentifier
}

type Pbes2Params struct {
	KeyDerivationFunc pkix.AlgorithmIdentifier
	EncryptionScheme  pkix.AlgorithmIdentifier
}

func (pbes *Pbes2Params) DeriveKey(password []byte, keyLength ...int) (key []byte, err pkerr.Kerror) {
	var params KDFParams
	params, err = parseKeyDerivationFunc(pbes.KeyDerivationFunc)
	if err != nil {
		return
	}
	if len(keyLength) > 0 {
		return params.DeriveKey(password, keyLength[0])
	}
	return params.DeriveKey(password, params.GetKeyLength())
}

func (pbes *Pbes2Params) PKCS12MacAlgorithmAndKey(password []byte) (func() hash.Hash, []byte, pkerr.Kerror) {
	key, err := pbes.DeriveKey(password)
	if err != nil {
		return nil, nil, err
	}

	switch {
	case pbes.EncryptionScheme.Algorithm.Equal(pkix.OidHMACWithSHA1.ToAsn1()):
		return sha1.New, key, nil
	case pbes.EncryptionScheme.Algorithm.Equal(pkix.OidHMACWithSHA256.ToAsn1()):
		return sha256.New, key, nil
	case pbes.EncryptionScheme.Algorithm.Equal(pkix.OidHMACWithSHA384.ToAsn1()):
		return sha512.New384, key, nil
	case pbes.EncryptionScheme.Algorithm.Equal(pkix.OidHMACWithSHA512.ToAsn1()):
		return sha512.New, key, nil
	default:
		return nil, nil, pkerr.NewErrUnsupportedPBMAC1Algorithm(pbes.EncryptionScheme.Algorithm.String())
	}

}

func parseKeyDerivationFunc(keyDerivationFunc pkix.AlgorithmIdentifier) (params KDFParams, err pkerr.Kerror) {
	params, err = NewKDFParams(keyDerivationFunc.Algorithm)
	if err == nil {
		_, err = asn1.Unmarshal(keyDerivationFunc.Parameters.FullBytes, params)
		if err != nil {
			return nil, pkerr.NewErrInvalidKDFParams(err)
		}
	}
	return
}

func parseEncryptionScheme(encryptionScheme pkix.AlgorithmIdentifier) (cipher Cipher, iv []byte, err pkerr.Kerror) {
	cipher, err = NewCipher(pkix.CipherOID(encryptionScheme.Algorithm))
	if err == nil {
		if _, err := asn1.Unmarshal(encryptionScheme.Parameters.FullBytes, &iv); err != nil {
			return nil, nil, pkerr.NewErrEncryptionParams()
		}
	}
	return
}

func ParsePBES2Params(data []byte) (params *Pbes2Params, err pkerr.Kerror) {
	var rest []byte
	params = &Pbes2Params{}
	rest, err = asn1.Unmarshal(data, params)
	if err == nil && len(rest) > 0 {
		err = pkerr.NewErrInvalidPBES2Params()
	}
	return
}

// ParsePrivateKey parses a DER-encoded PKCS#8 private key.
func ParseEncryptedPKCS5(encryptionAlgorithm pkix.AlgorithmIdentifier, encryptedData []byte, password []byte) ([]byte, pkerr.Kerror) {
	// No password provided, assume the private key is unencrypted
	if len(password) == 0 {
		return nil, pkerr.NewErrPasswordMissing()
	}

	if !encryptionAlgorithm.Algorithm.Equal(pkix.OidPBES2) {
		return nil, pkerr.NewErrPBES2Only()
	}

	params, err := ParsePBES2Params(encryptionAlgorithm.Parameters.FullBytes)
	if err != nil {
		return nil, err
	}

	cipher, iv, err := parseEncryptionScheme(params.EncryptionScheme)
	if err != nil {
		return nil, err
	}

	symkey, err := params.DeriveKey(password, cipher.KeySize())
	if err != nil {
		return nil, err
	}

	decryptedData, err := cipher.Decrypt(symkey, iv, encryptedData)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}

func MakePBES2(options ...*Opts) (ai *pkix.AlgorithmIdentifier, iv []byte, pbes *Pbes2Params, err pkerr.Kerror) {
	opts := NewDefaultOpts()
	if len(options) > 0 || options[0] != nil {
		opts = options[0]
	}

	iv = make([]byte, opts.Cipher.IVSize())
	_, errNative := rand.Read(iv)
	if errNative != nil {
		err = pkerr.NewErrNative(errNative)
		return
	}
	err = opts.KDFParams.MakeSalt(opts.SaltSize)
	if err != nil {
		return
	}
	marshalledParams, err := asn1.Marshal(opts.KDFParams.Param())
	if err != nil {
		return
	}
	marshalledIV, err := asn1.Marshal(iv)
	if err != nil {
		return
	}
	pbes = &Pbes2Params{
		EncryptionScheme: pkix.AlgorithmIdentifier{
			Algorithm:  opts.Cipher.OID(),
			Parameters: asn1.RawValue{FullBytes: marshalledIV},
		},
		KeyDerivationFunc: pkix.AlgorithmIdentifier{
			Algorithm:  opts.KDFParams.OID(),
			Parameters: asn1.RawValue{FullBytes: marshalledParams},
		},
	}
	marshalledEncryptionAlgorithmParams, err := asn1.Marshal(*pbes)
	if err != nil {
		return
	}

	oid := pkix.OidPBES2
	if opts.Oid != nil {
		oid = opts.Oid
	}

	ai = &pkix.AlgorithmIdentifier{
		Algorithm:  oid,
		Parameters: asn1.RawValue{FullBytes: marshalledEncryptionAlgorithmParams},
	}

	return
}

// MarshalPrivateKey encodes a private key into DER-encoded PKCS#8 with the given options.
func MarshalEncryptedPKCS5(data []byte, password []byte, options ...*Opts) (encryptionAlgorithm *pkix.AlgorithmIdentifier, encryptedData []byte, err pkerr.Kerror) {
	var iv, key []byte
	if len(password) == 0 {
		err = pkerr.NewErrPasswordMissing()
		return
	}

	opts := NewDefaultOpts()
	if len(options) > 0 || options[0] != nil {
		opts = options[0]
	}

	encryptionAlgorithm, iv, _, err = MakePBES2(options...)

	key, err = opts.KDFParams.DeriveKey(password, opts.Cipher.KeySize())
	if err != nil {
		return
	}
	encryptedData, err = opts.Cipher.Encrypt(key, iv, data)

	return
}
