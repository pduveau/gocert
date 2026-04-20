package pkix

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/pduveau/gocert/asn1"
)

func TestRSAPSAParameters(t *testing.T) {
	generateParams := func(hashFunc crypto.Hash) []byte {
		var hashOID asn1.ObjectIdentifier

		switch hashFunc {
		case crypto.SHA256:
			hashOID = OidSHA256
		case crypto.SHA384:
			hashOID = OidSHA384
		case crypto.SHA512:
			hashOID = OidSHA512
		}

		params := pssParameters{
			Hash: AlgorithmIdentifier{
				Algorithm:  hashOID,
				Parameters: asn1.NullRawValue,
			},
			MGF: AlgorithmIdentifier{
				Algorithm: OidMGF1,
			},
			SaltLength:   hashFunc.Size(),
			TrailerField: 1,
		}

		mgf1Params := AlgorithmIdentifier{
			Algorithm:  hashOID,
			Parameters: asn1.NullRawValue,
		}

		var err error
		params.MGF.Parameters.FullBytes, err = asn1.Marshal(mgf1Params)
		if err != nil {
			t.Fatalf("failed to marshal MGF parameters: %s", err)
		}

		serialized, err := asn1.Marshal(params)
		if err != nil {
			t.Fatalf("failed to marshal parameters: %s", err)
		}

		return serialized
	}

	for _, detail := range signatureAlgorithmDetails {
		if !detail.IsRSAPSS {
			continue
		}
		generated := generateParams(detail.Hash)
		if !bytes.Equal(detail.Params.FullBytes, generated) {
			t.Errorf("hardcoded parameters for %s didn't match generated parameters: got (generated) %x, wanted (hardcoded) %x", detail.Hash, generated, detail.Params.FullBytes)
		}
	}
}
