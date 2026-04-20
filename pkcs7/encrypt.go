package pkcs7

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/internal/intcrypto"
	"github.com/pduveau/gocert/pkerr"
	"github.com/pduveau/gocert/pkix"
	"github.com/pduveau/gocert/x509"
)

type envelopedData struct {
	Version              int
	RecipientInfos       []recipientInfo `asn1:"set"`
	EncryptedContentInfo encryptedContentInfo
}

type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

type recipientInfo struct {
	Version                int
	IssuerAndSerialNumber  issuerAndSerial
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"tag:0,optional,explicit"`
}

type EncryptionAlgorithm int

const (
	// EncryptionAlgorithmAES128CBC is the AES 128 bits with CBC intcrypto algorithm
	// Avoid this algorithm unless required for interoperability; use AES GCM instead.
	EncryptionAlgorithmAES128CBC EncryptionAlgorithm = iota + 1

	// EncryptionAlgorithmAES256CBC is the AES 256 bits with CBC intcrypto algorithm
	// Avoid this algorithm unless required for interoperability; use AES GCM instead.
	EncryptionAlgorithmAES256CBC

	// EncryptionAlgorithmAES128GCM is the AES 128 bits with GCM intcrypto algorithm
	EncryptionAlgorithmAES128GCM

	// EncryptionAlgorithmAES256GCM is the AES 256 bits with GCM intcrypto algorithm
	EncryptionAlgorithmAES256GCM
)

func (t EncryptionAlgorithm) String() string {
	switch t {
	case EncryptionAlgorithmAES128CBC:
		return "AES128CBC"
	case EncryptionAlgorithmAES256CBC:
		return "AES256CBC"
	case EncryptionAlgorithmAES128GCM:
		return "AES128GCM"
	case EncryptionAlgorithmAES256GCM:
		return "AES256GCM"
	}
	return "Unknown"
}

// ContentEncryptionAlgorithm determines the algorithm used to encrypt the
// plaintext message. Change the value of this variable to change which
// algorithm is used in the Encrypt() function.
// var ContentEncryptionAlgorithm = EncryptionAlgorithmAES256CBC

const nonceSize = 12

type aesGCMParameters struct {
	Nonce  []byte `asn1:"tag:4"`
	ICVLen int
}

func encryptAESGCM(ContentEncryptionAlgorithm EncryptionAlgorithm, content []byte, key []byte) ([]byte, *encryptedContentInfo, pkerr.Kerror) {
	var keyLen int
	var algID asn1.ObjectIdentifier
	switch ContentEncryptionAlgorithm {
	case EncryptionAlgorithmAES128GCM:
		keyLen = 16
		algID = pkix.OIDEncryptionAlgorithmAES128GCM
	case EncryptionAlgorithmAES256GCM:
		keyLen = 32
		algID = pkix.OIDEncryptionAlgorithmAES256GCM
	default:
		return nil, nil, pkerr.NewErrInvalidContentEncryptionAlgorithm("encryptAESGCM", ContentEncryptionAlgorithm.String())
	}
	if key == nil {
		// Create AES key
		key = make([]byte, keyLen)

		_, err := rand.Read(key)
		if err != nil {
			return nil, nil, pkerr.NewErrNative(err)
		}
	}

	// Create nonce
	nonce := make([]byte, nonceSize)

	_, errNative := rand.Read(nonce)
	if errNative != nil {
		return nil, nil, pkerr.NewErrNative(errNative)
	}

	// Encrypt content
	block, errNative := aes.NewCipher(key)
	if errNative != nil {
		return nil, nil, pkerr.NewErrNative(errNative)
	}

	gcm, errNative := cipher.NewGCM(block)
	if errNative != nil {
		return nil, nil, pkerr.NewErrNative(errNative)
	}

	ciphertext := gcm.Seal(nil, nonce, content, nil)

	// Prepare ASN.1 Encrypted Content Info
	paramSeq := aesGCMParameters{
		Nonce:  nonce,
		ICVLen: gcm.Overhead(),
	}

	paramBytes, err := asn1.Marshal(paramSeq)
	if errNative != nil {
		return nil, nil, err
	}

	eci := encryptedContentInfo{
		ContentType: OIDDataContentType,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: algID,
			Parameters: asn1.RawValue{
				Tag:   asn1.TagSequence,
				Bytes: paramBytes,
			},
		},
		EncryptedContent: marshalEncryptedContent(ciphertext),
	}

	return key, &eci, nil
}

func encryptAESCBC(ContentEncryptionAlgorithm EncryptionAlgorithm, content []byte, key []byte) ([]byte, *encryptedContentInfo, pkerr.Kerror) {
	var keyLen int
	var algID asn1.ObjectIdentifier
	switch ContentEncryptionAlgorithm {
	case EncryptionAlgorithmAES128CBC:
		keyLen = 16
		algID = pkix.OIDEncryptionAlgorithmAES128CBC
	case EncryptionAlgorithmAES256CBC:
		keyLen = 32
		algID = pkix.OIDEncryptionAlgorithmAES256CBC
	default:
		return nil, nil, pkerr.NewErrInvalidContentEncryptionAlgorithm("encryptAESCBC", ContentEncryptionAlgorithm.String())
	}

	if key == nil {
		// Create AES key
		key = make([]byte, keyLen)

		_, errNative := rand.Read(key)
		if errNative != nil {
			return nil, nil, pkerr.NewErrNative(errNative)
		}
	}

	// Create CBC IV
	iv := make([]byte, aes.BlockSize)
	_, errNative := rand.Read(iv)
	if errNative != nil {
		return nil, nil, pkerr.NewErrNative(errNative)
	}

	// Encrypt padded content
	block, errNative := aes.NewCipher(key)
	if errNative != nil {
		return nil, nil, pkerr.NewErrNative(errNative)
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	plaintext, err := intcrypto.Pad(content, mode.BlockSize())
	if errNative != nil {
		return nil, nil, err
	}
	cyphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(cyphertext, plaintext)

	// Prepare ASN.1 Encrypted Content Info
	eci := encryptedContentInfo{
		ContentType: OIDDataContentType,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  algID,
			Parameters: asn1.RawValue{Tag: 4, Bytes: iv},
		},
		EncryptedContent: marshalEncryptedContent(cyphertext),
	}

	return key, &eci, nil
}

// Encrypt creates and returns an envelope data PKCS7 structure with encrypted
// recipient keys for each recipient public key.
//
// The algorithm used to perform intcrypto is determined by the current value
// of the global ContentEncryptionAlgorithm package variable. By default, the
// value is EncryptionAlgorithmDESCBC. To use a different algorithm, change the
// value before calling Encrypt(). For example:
//
//	ContentEncryptionAlgorithm = EncryptionAlgorithmAES128GCM
//
// TODO(fullsailor): Add support for encrypting content with other algorithms
func Encrypt(ContentEncryptionAlgorithm EncryptionAlgorithm, content []byte, recipients []*x509.Certificate) ([]byte, pkerr.Kerror) {
	var eci *encryptedContentInfo
	var key []byte
	var err pkerr.Kerror

	// Apply chosen symmetric intcrypto method
	switch ContentEncryptionAlgorithm {
	case EncryptionAlgorithmAES128CBC, EncryptionAlgorithmAES256CBC:
		key, eci, err = encryptAESCBC(ContentEncryptionAlgorithm, content, nil)
	case EncryptionAlgorithmAES128GCM, EncryptionAlgorithmAES256GCM:
		key, eci, err = encryptAESGCM(ContentEncryptionAlgorithm, content, nil)

	default:
		return nil, pkerr.NewErrUnsupportedEncryptionAlgorithm(ContentEncryptionAlgorithm.String())
	}

	if err != nil {
		return nil, err
	}

	// Prepare each recipient's encrypted cipher key
	recipientInfos := make([]recipientInfo, len(recipients))
	for i, recipient := range recipients {
		encrypted, err := encryptKey(key, recipient)
		if err != nil {
			return nil, err
		}
		ias, err := cert2issuerAndSerial(recipient)
		if err != nil {
			return nil, err
		}
		info := recipientInfo{
			Version:               0,
			IssuerAndSerialNumber: ias,
			KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: pkix.OIDSignatureAlgorithmRSASHA256,
			},
			EncryptedKey: encrypted,
		}
		recipientInfos[i] = info
	}

	// Prepare envelope content
	envelope := envelopedData{
		EncryptedContentInfo: *eci,
		Version:              0,
		RecipientInfos:       recipientInfos,
	}
	innerContent, err := asn1.Marshal(envelope)
	if err != nil {
		return nil, err
	}

	// Prepare outer payload structure
	wrapper := contentInfo{
		ContentType: OIDEnvelopedDataContentType,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: innerContent},
	}

	return asn1.Marshal(wrapper)
}

// EncryptUsingPSK creates and returns an encrypted data PKCS7 structure,
// encrypted using caller provided pre-shared secret.
func EncryptUsingPSK(ContentEncryptionAlgorithm EncryptionAlgorithm, content []byte, key []byte) ([]byte, pkerr.Kerror) {
	var eci *encryptedContentInfo
	var err pkerr.Kerror

	if key == nil {
		return nil, pkerr.NewErrNoPSK()
	}

	// Apply chosen symmetric intcrypto method
	switch ContentEncryptionAlgorithm {
	case EncryptionAlgorithmAES128GCM, EncryptionAlgorithmAES256GCM:
		_, eci, err = encryptAESGCM(ContentEncryptionAlgorithm, content, key)

	default:
		return nil, pkerr.NewErrUnsupportedEncryptionAlgorithm(ContentEncryptionAlgorithm.String())
	}

	if err != nil {
		return nil, err
	}

	// Prepare encrypted-data content
	ed := encryptedData{
		Version:              0,
		EncryptedContentInfo: *eci,
	}
	innerContent, err := asn1.Marshal(ed)
	if err != nil {
		return nil, err
	}

	// Prepare outer payload structure
	wrapper := contentInfo{
		ContentType: OIDEncryptedDataContentType,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: innerContent},
	}

	return asn1.Marshal(wrapper)
}

func marshalEncryptedContent(content []byte) asn1.RawValue {
	asn1Content, _ := asn1.Marshal(content)
	return asn1.RawValue{Tag: 0, Class: 2, Bytes: asn1Content, IsCompound: true}
}

func encryptKey(key []byte, recipient *x509.Certificate) ([]byte, pkerr.Kerror) {
	if pub := recipient.PublicKey.(*rsa.PublicKey); pub != nil {
		out, err := rsa.EncryptPKCS1v15(rand.Reader, pub, key)
		if err != nil {
			return nil, pkerr.NewErrNative(err)
		}
		return out, nil
	}
	return nil, pkerr.NewErrUnsupportedEncryptionAlgorithm(recipient.PublicKeyAlgorithm.String())
}
