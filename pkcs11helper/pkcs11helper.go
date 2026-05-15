package pkcs11helper

import (
	"crypto"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/internal/pkixstring"
	"github.com/pduveau/gocert/keys"
	"github.com/pduveau/gocert/pkerr"
	"github.com/pduveau/gocert/pkix"
)

func ParseNameFromPKCS11der(der []byte) (n *pkix.Name, err pkerr.Kerror) {
	var in = pkixstring.String(der)
	var r *pkix.RDNSequence
	n = &pkix.Name{}
	r, err = in.ParseName()
	n.FillFromRDNSequence(r)
	return
}

func PublicKeyToPublicKeyInfo(pkey crypto.PublicKey) (pk keys.PublicKeyInfo, err pkerr.Kerror) {
	key, algo, err := keys.MarshalPublicKey(pkey)
	if err != nil {
		return
	}

	return keys.PublicKeyInfo{
		Algorithm: algo,
		PublicKey: asn1.BitString{
			Bytes:     key,
			BitLength: len(key) * 8},
	}, nil
}
