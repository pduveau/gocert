package intcrypto

import (
	"bytes"

	"github.com/pduveau/gocert/pkerr"
)

func Unpad(data []byte, blocklen int) ([]byte, pkerr.Kerror) {
	if blocklen < 1 {
		return nil, pkerr.NewErrEncryptionBocklen(blocklen)
	}
	if len(data)%blocklen != 0 || len(data) == 0 {
		return nil, pkerr.NewErrEncryptionDatalen(len(data))
	}

	// the last byte is the length of padding
	padlen := int(data[len(data)-1])
	if padlen > blocklen {
		return nil, pkerr.NewErrEncryptionData()
	}

	// check padding integrity, all bytes should be the same
	pad := data[len(data)-padlen:]
	for _, padbyte := range pad {
		if padbyte != byte(padlen) {
			return nil, pkerr.NewErrEncryptionPadding()
		}
	}

	return data[:len(data)-padlen], nil
}

func Pad(data []byte, blocklen int) ([]byte, pkerr.Kerror) {
	if blocklen < 1 {
		return nil, pkerr.NewErrEncryptionBocklen(blocklen)
	}
	padlen := blocklen - (len(data) % blocklen)
	if padlen == 0 {
		padlen = blocklen
	}
	pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
	return append(data, pad...), nil
}
