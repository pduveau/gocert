// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/pem"
	"reflect"
	"testing"

	"github.com/pduveau/gocert/pkcs8"
	"github.com/pduveau/gocert/x509"
)

func TestPBES2_AES256CBC(t *testing.T) {
	// This P12 PDU is a self-signed certificate exported via Windows certmgr.
	// It is encrypted with the following options (verified via openssl): PBES2, PBKDF2, AES-256-CBC, Iteration 2000, PRF hmacWithSHA256
	commonName := "*.ad.standalone.com"
	base64P12 := `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`
	p12, _ := base64.StdEncoding.DecodeString(base64P12)
	pk, cert, caCerts, err := DecodeChain(p12, "password")
	if err != nil {
		t.Fatal(err)
	}

	rsaPk, ok := pk.(*rsa.PrivateKey)
	if !ok {
		t.Error("could not cast to rsa private key")
	}
	if !rsaPk.PublicKey.Equal(cert.PublicKey) {
		t.Error("public key embedded in private key not equal to public key of certificate")
	}
	if len(cert.Subject.CommonName) == 0 || cert.Subject.CommonName[0] != commonName {
		t.Errorf("unexpected leaf cert common name, got %s, want %s", cert.Subject.CommonName, commonName)
	}
	if len(caCerts) != 0 {
		t.Errorf("unexpected # of caCerts: got %d, want 0", len(caCerts))
	}
}

func TestPBES2_AES128CBC(t *testing.T) {
	//PKCS7 Encrypted data: PBES2, PBKDF2, AES-128-CBC, Iteration 2048, PRF hmacWithSHA256
	commonName := "example-com"
	base64P12 := `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`

	p12, _ := base64.StdEncoding.DecodeString(base64P12)
	pk, cert, caCerts, err := DecodeChain(p12, "rHyQTJsubhfxcpH5JttyilHE6BBsNoZp")
	if err != nil {
		t.Fatal(err)
	}

	rsaPk, ok := pk.(*rsa.PrivateKey)
	if !ok {
		t.Error("could not cast to rsa private key")
	}
	if !rsaPk.PublicKey.Equal(cert.PublicKey) {
		t.Error("public key embedded in private key not equal to public key of certificate")
	}
	if len(cert.Subject.CommonName) == 0 || cert.Subject.CommonName[0] != commonName {
		t.Errorf("unexpected leaf cert common name, got %s, want %s", cert.Subject.CommonName, commonName)
	}
	if len(caCerts) != 0 {
		t.Errorf("unexpected # of caCerts: got %d, want 0", len(caCerts))
	}
}

func TestPBES2_AES192CBC(t *testing.T) {
	//PKCS7 Encrypted data: PBES2, PBKDF2, AES-192-CBC, Iteration 2048, PRF hmacWithSHA256
	commonName := "example-com"
	base64P12 := `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`

	p12, _ := base64.StdEncoding.DecodeString(base64P12)
	pk, cert, caCerts, err := DecodeChain(p12, "password")
	if err != nil {
		t.Fatal(err)
	}

	rsaPk, ok := pk.(*rsa.PrivateKey)
	if !ok {
		t.Error("could not cast to rsa private key")
	}
	if !rsaPk.PublicKey.Equal(cert.PublicKey) {
		t.Error("public key embedded in private key not equal to public key of certificate")
	}
	if len(cert.Subject.CommonName) == 0 || cert.Subject.CommonName[0] != commonName {
		t.Errorf("unexpected leaf cert common name, got %s, want %s", cert.Subject.CommonName, commonName)
	}
	if len(caCerts) != 0 {
		t.Errorf("unexpected # of caCerts: got %d, want 0", len(caCerts))
	}
}

var leaf_pem = []byte(`-----BEGIN CERTIFICATE-----
MIIDzjCCAragAwIBAgICIAkwDQYJKoZIhvcNAQELBQAwOzELMAkGA1UEBhMCZnIx
DjAMBgNVBAoMBWFzYXZpMQ8wDQYDVQQDDAZhYzIwNDgxCzAJBgNVBAsMAjJrMB4X
DTI2MDQxMzIwMzczMVoXDTI5MDQxMzIwMzczMVowODELMAkGA1UEBhMCZnIxDjAM
BgNVBAoMBWFzYXZpMQswCQYDVQQLDAIyazEMMAoGA1UEAwwDZm9vMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxEjCjsEtCvAipKGI5WtkPe23A0lwIvK5
eP8aeGMpB+vrF3XlktbK07O2O2aU47pWjn/DsWa1oouVQQHRG7W1rVL2NiBvkH58
Wr8NmrZRzvcy/ZuGdyMo2Q3Z5mBhm18X/tTZiJjoduZn3o1zT2SEg4aGjNv31S3e
vxT6JRMupfpkCaKAYjPhy2ykpNHsjD0g+dlq7FG8HmCD3vtLCdneOBAmWtLe8Rdo
G7cJ+AmGec1Q7S8nZ5Ch/MOIXB+8huYcT23NFuOrzongQ/yFDXaUGjkKKBmnJFz5
GKh7NdZogEAoqAJgNmpQ4FB+VATvi+qZ1PhkpOSsVXmiI3n/WIdkPQIDAQABo4He
MIHbMAkGA1UdEwQCMAAwEQYJYIZIAYb4QgEBBAQDAgWgMDMGCWCGSAGG+EIBDQQm
FiRPcGVuU1NMIEdlbmVyYXRlZCBDbGllbnQgQ2VydGlmaWNhdGUwHQYDVR0OBBYE
FCQ8Y7BbC3ox9F97cgs1UPFV7sQaMB8GA1UdIwQYMBaAFGAuvIojZHBg08QCQBrY
9uDXqPkAMA4GA1UdDwEB/wQEAwIF4DAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYB
BQUHAwQwFwYDVR0RBBAwDoEMZm9vQGFzYXZpLmZyMA0GCSqGSIb3DQEBCwUAA4IB
AQABQPNKeQrg659jHbXO1/lvfXfn0cny015fpNMmJV1c6dqxTX9lWl1+jHrfG4zS
NQWjOSuLrWvbCMIP+TCce3fgQKTFB6eDP67E2qxIHMcubfaG0BTEbO37ie1eHAOI
SNja2MU4gYKrM/UMZpzsHkyu2MoIh/gj/V+o+A5UImWk5WRJWUh9yXRs/Cc1mbyQ
HG2GgNomEDMubRKHwesRqX9lPr9/2OEEaz5lwfZGfkLY6YBClon1h6aR25tk6ume
qh3v/cLR6DTWrqxokO4+Ebu/SYV1G0S8J00lV+FBWAsd1DantWOKCnwMsDa3xXh3
0hu9ouWpo24x4rvlJqENk9TB
-----END CERTIFICATE-----`)

var caroot_pem = []byte(`-----BEGIN CERTIFICATE-----
MIIDejCCAmKgAwIBAgIUAqz9ONHq/mIO3L8kIT38vgVXBrAwDQYJKoZIhvcNAQEL
BQAwOzELMAkGA1UEBhMCZnIxDjAMBgNVBAoMBWFzYXZpMQ8wDQYDVQQDDAZhYzIw
NDgxCzAJBgNVBAsMAjJrMB4XDTIxMDEyMzIxMjA0OVoXDTMxMDEyNDIxMjA0OVow
OzELMAkGA1UEBhMCZnIxDjAMBgNVBAoMBWFzYXZpMQ8wDQYDVQQDDAZhYzIwNDgx
CzAJBgNVBAsMAjJrMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Rd+
unleNnzJzRhK1ytI7dPhKx6L6ppB+KsgsgcbdXCl3JYbhELQX961vs4uE6Lela/2
ERNIshtqi+qlbmq6l0vPxm3ShvzmJTvzf6arlml+tKQz3dicWeipN9Ev941o/GCa
FZeWFjo0BT8j1zZlg+jeJEgq66JRfoV/PEOsIPsSSHKB4ohxqxERzCp7LiW+zetG
hyGRiuEPBnG47vToyKxqDJgvAyXIzqPqFfGwb6Qt/PVk2SRA4S82g0/0VoN7H1I/
yFrwR4DdkeUvO7+fc7qyvhNMLpCErsYpnC4K5pFFq4QQt/2xUJdo+zB6BVrnGozk
Lf2nMg391a1H/zCezQIDAQABo3YwdDAdBgNVHQ4EFgQUYC68iiNkcGDTxAJAGtj2
4Neo+QAwHwYDVR0jBBgwFoAUYC68iiNkcGDTxAJAGtj24Neo+QAwDwYDVR0TAQH/
BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwEQYJYIZIAYb4QgEBBAQDAgEGMA0GCSqG
SIb3DQEBCwUAA4IBAQBJsrqJK7JKc6NB5MlPlE+rA739UJFU28yPOjr8fc9E1C+O
P1pkgOs6CYiG9WWQCih1Tv0cucnHKELYN7jnhT6DiTXmvjayrmOXTlujzijSLdT7
Mz9OyD+ifyUn6HPzjWjwcFhKR+QC4Z8jaoK7WTV7+gtTwlloyTEaJcVl2blVyLbx
SeWt2hCO8i3PxRKym/FBDzrzN66z8HEAdWQ2b4IbqBkbKgJN8TaHnH5FU4k9qVZx
tzSQo0gc6qPnCcqGvH0EJsxOFCb5RqyPSYT3tywPzKPB809ZkntqTiaNHces6NhV
vhUgUvMQSWW+CpmOcfqJrW6LsS0NZwVvhil8nEJ+
-----END CERTIFICATE-----`)

var pkey_pem = []byte(`-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIxqFPKzSBV30CAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBCwsWfRNEJJZc400PBShcVXBIIE
0EvqGAWqmYF7PMXOg97lMXYTAS0710XUH3qEEH4c27erHofjXFzC4F/eN6Urxgru
Ah0qfWj5/DDjCrPXHPdZ64P9sW+DVIbeVxNR8OQcoVUOBZwWtHYYG+fuuWlJRiwS
rkfF6n03SoNl/6AB0QZ9cieDeJR42VSvzJqC/tYk6y46H0JJFqkmazZOWKwd3tRt
IniEeGOiH90i3EAWaNpPb1UhYiN0PCHq+660lwK8d6MU2yiHWskUYslLuyZp/Z6y
RRUL+fGGKSn6bUVkmRhYGprzjVJnq17r1ToO5t/ezKacX/pTEECXQTCQa1EKSe1V
dzsuWoIkLEjl9yH0gT6b5sKXmusNCmwORAs1+7qHneIoHyDS55bSQklP9N3NiK0Z
xr0WGP3Z6eVq+AYpLPvtnO17zVIRDkocNxjwVU2UFzch4SVH/xxAy9nvY2O91q5x
38kF7quCrh+L40Xj/8/pyIagx29bP9Jog3zHklKPvgYDVhyDwahBWoWlsZBhbDZ+
IMwc/wtuB9uqpJUES1gm/+bt76mclvAIo7A6zzmpH+P28KfK1wvfGSQBS7WNmClX
+EaVkY4EdGLJOkxIoY37Zw8vHFMM7KvSplORDZC6tHgSKZTkiM5Vz0u2VasoVLii
8Vh8cFsOCimhc6/pvhn+guKnA0qkbJDqlg7Rw8fjfjca5VyFf5zaoV+WEDbTJ/Wi
lt/ALx0NNU13ABZtxrrHVwlwsElHp5KlHuQd4Urk3Lsocf3LCfayYdgAo6zfZAa5
H1b6dujqls6kZ7fiPLygghwHTGI+Mt4IxVm5JLe4FXxhAfDm9i+rp5o1HDkyHwES
Tu5gYE0xUY1e8ZhPjvXStK3DPxCpRjYnzmS9wux24bWtRnSf+JQhSRmP6UASVFSC
n2ENLxRKh6pHCV4u1Ck9lsaJpM3vj7LTTk2tUi8+AjVFZuWDYb+h2pgK3jdm5IGU
OqJhSZD1iJRMfeHj6iz2w2JWovpK7lF/X57hEjNzkf6HtjgO6z0vFkwQ159krvIa
BG3SY74PDQ0YEHRMIKO7XqT9y8j+i97xsRZ091ocobbcJmD0huY/dFnneJ7HOrDS
7LkWngr0daa5Wzatrwbgx5f1t44Yw3MHLa8ANNUcVwtx1OYcVinaXhm6f5v7w0aQ
hDO4NOknrcO4v/KBcd32ZJP599fLUTVSEIYjSvX3d7TmUmwXym1oMjEe4lkZNFDk
nxqe0cG4MC0z/mxASTFOTLlfwlvStLLI9LPVn/w8qWu9JAaeBPhwkwLajXtlhYz3
aitKKjXZB8or/NzP9ONtIMqEK023hfHlPtobHCq9DEU3KZCEAaR+OZRGMLxKr1Q6
CmCNiNF/ISstETdqDwqSOgDGp7QH3Z0lIAyNwtWAjg4acvQPRwOvF/WdJ9befQx3
H9OjHZY2q/C9haRF5dGhEnU1y0pTdEjntA2hpOelfU0PsfH1sDTk+MzG5GWEOxt/
9YJrKkBcI79+82Hiv7MKnR8h0gMsV8OBBJPPBzgsWLRc0PLIFCxr+T8NKQ7aoYaa
pK4SakyX8UVB2Kja7TSmk/g4+zVyPue2Gqm6+k+xD1VJugpll/GBoUx249NtWhHL
2ATWEsbEEu4VPa0EX+Ok3zuRrozv5YmROTqtA5hwvHVv
-----END ENCRYPTED PRIVATE KEY-----`)

func TestRoundtripToPKCS12(t *testing.T) {
	key_der, _ := pem.Decode(pkey_pem)
	caroot_der, _ := pem.Decode(caroot_pem)
	leaf_der, _ := pem.Decode(leaf_pem)

	key, err := pkcs8.ParsePKCS8EncryptedPrivateKey(key_der.Bytes, []byte("password"))
	if err != nil {
		t.Fatal("ENCRYPTED PRIVATE KEY: error parsing")
	}

	caroot, err := x509.ParseCertificate(caroot_der.Bytes)
	if err != nil {
		t.Fatal("CAROOT: error parsing")
	}

	leaf, err := x509.ParseCertificate(leaf_der.Bytes)
	if err != nil {
		t.Fatal("LEAF: error parsing")
	}

	pxfdata, err := Encode(false, key, leaf, []*x509.Certificate{caroot}, "password")
	if err != nil {
		t.Fatalf("PKCS12: error encoding with PBMAC1 %v", err)
	}

	keyOut, leafOut, carootOut, err := DecodeChain(pxfdata, "password")
	if err != nil {
		t.Fatal("PKCS12: error decoding with PBMAC1")
	}

	if !reflect.DeepEqual(key, keyOut) {
		t.Errorf("Private key are different with PBMAC1")
	}
	if !reflect.DeepEqual(leaf, leafOut) {
		t.Errorf("Leaf certificate are different with PBMAC1")
	}
	if len(carootOut) == 0 || !reflect.DeepEqual(caroot, carootOut[0]) {
		t.Errorf("Root certificate are different with PBMAC1")
	}

	pxfdata, err = Encode(true, key, leaf, []*x509.Certificate{caroot}, "password")
	if err != nil {
		t.Fatalf("PKCS12: error encoding with PBMAC1 %v", err)
	}

	keyOut, leafOut, carootOut, err = DecodeChain(pxfdata, "password")
	if err != nil {
		t.Fatal("PKCS12: error decoding with PBMAC1")
	}

	if !reflect.DeepEqual(key, keyOut) {
		t.Errorf("Private key are different with PBMAC1")
	}
	if !reflect.DeepEqual(leaf, leafOut) {
		t.Errorf("Leaf certificate are different with PBMAC1")
	}
	if len(carootOut) == 0 || !reflect.DeepEqual(caroot, carootOut[0]) {
		t.Errorf("Root certificate are different with PBMAC1")
	}

}

func TestRoundtripToTrustStore(t *testing.T) {
	caroot_der, _ := pem.Decode(caroot_pem)
	leaf_der, _ := pem.Decode(leaf_pem)

	caroot, err := x509.ParseCertificate(caroot_der.Bytes)
	if err != nil {
		t.Fatal("CAROOT: error parsing")
	}

	leaf, err := x509.ParseCertificate(leaf_der.Bytes)
	if err != nil {
		t.Fatal("LEAF: error parsing")
	}

	pxfdata, err := EncodeTrustStore([]*x509.Certificate{caroot, leaf}, "password")
	if err != nil {
		t.Fatal("PKCS12: error encoding")
	}

	certOut, err := DecodeTrustStore(pxfdata, "password")
	if err != nil {
		t.Fatal("PKCS12: error decoding")
	}

	if len(certOut) != 2 {
		t.Errorf("Number of certificate are not two")
	} else {
		if !reflect.DeepEqual(caroot, certOut[0]) {
			t.Errorf("Certificate 1 are different ")
		}
		if !reflect.DeepEqual(leaf, certOut[1]) {
			t.Errorf("Certificate 1 are different ")
		}
	}
}
