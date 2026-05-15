package intcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/pkerr"
	"github.com/pduveau/gocert/pkix"
)

var (
	// Decryption only Algorithms for compatibility
	oidDecryptionAlgorithmDESCBC     = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7}
	oidDecryptionAlgorithmDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
)

const nonceSize = 12

type aesGCMParameters struct {
	Nonce  []byte `asn1:"tag:4"`
	ICVLen int
}

func Decrypt(alg asn1.ObjectIdentifier, paramBytes, key, cyphertext []byte) ([]byte, pkerr.Kerror) {
	var block cipher.Block
	var nativeError error

	switch {
	case alg.Equal(oidDecryptionAlgorithmDESCBC):
		block, nativeError = des.NewCipher(key)
	case alg.Equal(oidDecryptionAlgorithmDESEDE3CBC):
		block, nativeError = des.NewTripleDESCipher(key)
	default:
		block, nativeError = aes.NewCipher(key)
	}

	if nativeError != nil {
		return nil, pkerr.NewErrNative(nativeError)
	}

	if alg.Equal(pkix.OIDEncryptionAlgorithmAES128GCM) || alg.Equal(pkix.OIDEncryptionAlgorithmAES256GCM) {
		params := aesGCMParameters{}

		_, perr := asn1.Unmarshal(paramBytes, &params)
		if perr != nil {
			return nil, perr
		}

		gcm, nativeError := cipher.NewGCM(block)
		if nativeError != nil {
			return nil, pkerr.NewErrNative(nativeError)
		}

		if len(params.Nonce) != gcm.NonceSize() {
			return nil, pkerr.NewErrEncryptionParams()
		}
		if params.ICVLen != gcm.Overhead() {
			return nil, pkerr.NewErrEncryptionParams()
		}

		plaintext, nativeError := gcm.Open(nil, params.Nonce, cyphertext, nil)
		if nativeError != nil {
			return nil, pkerr.NewErrNative(nativeError)
		}

		return plaintext, nil
	}

	if len(paramBytes) != block.BlockSize() {
		return nil, pkerr.NewErrEncryptionParams()
	}
	mode := cipher.NewCBCDecrypter(block, paramBytes)
	plaintext := make([]byte, len(cyphertext))
	mode.CryptBlocks(plaintext, cyphertext)

	return Unpad(plaintext, mode.BlockSize())
}

func EncryptAESGCM(content []byte, key []byte) (ciphertext []byte, params *asn1.RawValue, perr pkerr.Kerror) {
	var block cipher.Block
	var gcm cipher.AEAD
	var paramBytes []byte
	var nativeError error
	// Create nonce
	nonce := make([]byte, nonceSize)

	_, nativeError = rand.Read(nonce)
	if nativeError != nil {
		perr = pkerr.NewErrNative(nativeError)
		return
	}

	// Encrypt content
	block, nativeError = aes.NewCipher(key)
	if nativeError != nil {
		perr = pkerr.NewErrNative(nativeError)
		return
	}

	gcm, nativeError = cipher.NewGCM(block)
	if nativeError != nil {
		perr = pkerr.NewErrNative(nativeError)
		return
	}

	ciphertext = gcm.Seal(nil, nonce, content, nil)

	// Prepare ASN.1 Encrypted Content Info
	paramBytes, perr = asn1.Marshal(aesGCMParameters{
		Nonce:  nonce,
		ICVLen: gcm.Overhead(),
	})
	if perr != nil {
		return
	}

	params = &asn1.RawValue{
		Tag:   asn1.TagSequence,
		Bytes: paramBytes,
	}

	return
}

func EncryptAESCBC(content, iv, key []byte) (encryptedText []byte, params *asn1.RawValue, perr pkerr.Kerror) {
	// Encrypt padded content
	var block cipher.Block
	var nativeError error

	block, nativeError = aes.NewCipher(key)
	if nativeError != nil {
		perr = pkerr.NewErrNative(nativeError)
		return
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	encryptedText, perr = Pad(content, mode.BlockSize())
	if perr != nil {
		return
	}
	mode.CryptBlocks(encryptedText, encryptedText)

	params = &asn1.RawValue{Tag: asn1.TagOctetString, Bytes: iv}

	return
}

func Encrypt(gcm bool, content, iv, key []byte) ([]byte, *asn1.RawValue, pkerr.Kerror) {
	if gcm {
		return EncryptAESGCM(content, key)
	}
	return EncryptAESCBC(content, iv, key)
}
