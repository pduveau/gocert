package pkcs10

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/pem"
	"net"
	"net/url"
	"reflect"
	"slices"
	"testing"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/pkcs1"
	"github.com/pduveau/gocert/pkix"
	"github.com/pduveau/gocert/x509"
)

// These CSR was generated with OpenSSL:
//
//	openssl req -out CSR.csr -new -sha256 -nodes -keyout privateKey.key -config openssl.cnf
//
// With openssl.cnf containing the following sections:
//
//	[ v3_req ]
//	basicConstraints = CA:FALSE
//	keyUsage = nonRepudiation, digitalSignature, keyEncipherment
//	subjectAltName = email:gopher@golang.org,DNS:test.example.com
//	[ req_attributes ]
//	challengePassword = ignored challenge
//	unstructuredName  = ignored unstructured name
var csrBase64Array = [...]string{
	// Just [ v3_req ]
	"MIIDHDCCAgQCAQAwfjELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEUMBIGA1UEAwwLQ29tbW9uIE5hbWUxITAfBgkqhkiG9w0BCQEWEnRlc3RAZW1haWwuYWRkcmVzczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK1GY4YFx2ujlZEOJxQVYmsjUnLsd5nFVnNpLE4cV+77sgv9NPNlB8uhn3MXt5leD34rm/2BisCHOifPucYlSrszo2beuKhvwn4+2FxDmWtBEMu/QA16L5IvoOfYZm/gJTsPwKDqvaR0tTU67a9OtxwNTBMI56YKtmwd/o8d3hYv9cg+9ZGAZ/gKONcg/OWYx/XRh6bd0g8DMbCikpWgXKDsvvK1Nk+VtkDO1JxuBaj4Lz/p/MifTfnHoqHxWOWl4EaTs4Ychxsv34/rSj1KD1tJqorIv5Xv2aqv4sjxfbrYzX4kvS5SC1goIovLnhj5UjmQ3Qy8u65eow/LLWw+YFcCAwEAAaBZMFcGCSqGSIb3DQEJDjFKMEgwCQYDVR0TBAIwADALBgNVHQ8EBAMCBeAwLgYDVR0RBCcwJYERZ29waGVyQGdvbGFuZy5vcmeCEHRlc3QuZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEBAB6VPMRrchvNW61Tokyq3ZvO6/NoGIbuwUn54q6l5VZW0Ep5Nq8juhegSSnaJ0jrovmUgKDN9vEo2KxuAtwG6udS6Ami3zP+hRd4k9Q8djJPb78nrjzWiindLK5Fps9U5mMoi1ER8ViveyAOTfnZt/jsKUaRsscY2FzE9t9/o5moE6LTcHUS4Ap1eheR+J72WOnQYn3cifYaemsA9MJuLko+kQ6xseqttbh9zjqd9fiCSh/LNkzos9c+mg2yMADitaZinAh+HZi50ooEbjaT3erNq9O6RqwJlgD00g6MQdoz9bTAryCUhCQfkIaepmQ7BxS0pqWNW3MMwfDwx/Snz6g=",
	// Both [ v3_req ] and [ req_attributes ]
	"MIIDaTCCAlECAQAwfjELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEUMBIGA1UEAwwLQ29tbW9uIE5hbWUxITAfBgkqhkiG9w0BCQEWEnRlc3RAZW1haWwuYWRkcmVzczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK1GY4YFx2ujlZEOJxQVYmsjUnLsd5nFVnNpLE4cV+77sgv9NPNlB8uhn3MXt5leD34rm/2BisCHOifPucYlSrszo2beuKhvwn4+2FxDmWtBEMu/QA16L5IvoOfYZm/gJTsPwKDqvaR0tTU67a9OtxwNTBMI56YKtmwd/o8d3hYv9cg+9ZGAZ/gKONcg/OWYx/XRh6bd0g8DMbCikpWgXKDsvvK1Nk+VtkDO1JxuBaj4Lz/p/MifTfnHoqHxWOWl4EaTs4Ychxsv34/rSj1KD1tJqorIv5Xv2aqv4sjxfbrYzX4kvS5SC1goIovLnhj5UjmQ3Qy8u65eow/LLWw+YFcCAwEAAaCBpTAgBgkqhkiG9w0BCQcxEwwRaWdub3JlZCBjaGFsbGVuZ2UwKAYJKoZIhvcNAQkCMRsMGWlnbm9yZWQgdW5zdHJ1Y3R1cmVkIG5hbWUwVwYJKoZIhvcNAQkOMUowSDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF4DAuBgNVHREEJzAlgRFnb3BoZXJAZ29sYW5nLm9yZ4IQdGVzdC5leGFtcGxlLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAgxe2N5O48EMsYE7o0rZBB0wi3Ov5/yYfnmmVI22Y3sP6VXbLDW0+UWIeSccOhzUCcZ/G4qcrfhhx6gTZTeA01nP7TdTJURvWAH5iFqj9sQ0qnLq6nEcVHij3sG6M5+BxAIVClQBk6lTCzgphc835Fjj6qSLuJ20XHdL5UfUbiJxx299CHgyBRL+hBUIPfz8p+ZgamyAuDLfnj54zzcRVyLlrmMLNPZNll1Q70RxoU6uWvLH8wB8vQe3Q/guSGubLyLRTUQVPh+dw1L4t8MKFWfX/48jwRM4gIRHFHPeAAE9D9YAoqdIvj/iFm/eQ++7DP8MDwOZWsXeB6jjwHuLmkQ==",
}

var pemPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCxoeCUW5KJxNPxMp+KmCxKLc1Zv9Ny+4CFqcUXVUYH69L3mQ7v
IWrJ9GBfcaA7BPQqUlWxWM+OCEQZH1EZNIuqRMNQVuIGCbz5UQ8w6tS0gcgdeGX7
J7jgCQ4RK3F/PuCM38QBLaHx988qG8NMc6VKErBjctCXFHQt14lerd5KpQIDAQAB
AoGAYrf6Hbk+mT5AI33k2Jt1kcweodBP7UkExkPxeuQzRVe0KVJw0EkcFhywKpr1
V5eLMrILWcJnpyHE5slWwtFHBG6a5fLaNtsBBtcAIfqTQ0Vfj5c6SzVaJv0Z5rOd
7gQF6isy3t3w9IF3We9wXQKzT6q5ypPGdm6fciKQ8RnzREkCQQDZwppKATqQ41/R
vhSj90fFifrGE6aVKC1hgSpxGQa4oIdsYYHwMzyhBmWW9Xv/R+fPyr8ZwPxp2c12
33QwOLPLAkEA0NNUb+z4ebVVHyvSwF5jhfJxigim+s49KuzJ1+A2RaSApGyBZiwS
rWvWkB471POAKUYt5ykIWVZ83zcceQiNTwJBAMJUFQZX5GDqWFc/zwGoKkeR49Yi
MTXIvf7Wmv6E++eFcnT461FlGAUHRV+bQQXGsItR/opIG7mGogIkVXa3E1MCQARX
AAA7eoZ9AEHflUeuLn9QJI/r0hyQQLEtrpwv6rDT1GCWaLII5HJ6NUFVf4TTcqxo
6vdM4QGKTJoO+SaCyP0CQFdpcxSAuzpFcKv0IlJ8XzS/cy+mweCMwyJ1PFEc4FX6
wg/HcAJWY60xZTJDFN+Qfx8ZQvBEin6c2/h+zZi5IVY=
-----END RSA PRIVATE KEY-----
`

var testPrivateKey *rsa.PrivateKey

func init() {
	block, _ := pem.Decode([]byte(pemPrivateKey))

	var err error
	if testPrivateKey, err = pkcs1.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		panic("Failed to parse private key: " + err.Error())
	}
}

func TestCreateCertificateRequest(t *testing.T) {
	random := rand.Reader

	ecdsa256Priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %s", err)
	}

	ecdsa384Priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %s", err)
	}

	ecdsa521Priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %s", err)
	}

	_, ed25519Priv, err := ed25519.GenerateKey(random)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %s", err)
	}

	tests := []struct {
		name    string
		priv    any
		sigAlgo pkix.SignatureAlgorithm
	}{
		{"RSA", testPrivateKey, pkix.RSAWithSHA256},
		{"RSA-PSS-SHA256", testPrivateKey, pkix.RSAPSSWithSHA256},
		{"ECDSA-256", ecdsa256Priv, pkix.ECDSAWithSHA256},
		{"ECDSA-384", ecdsa384Priv, pkix.ECDSAWithSHA256},
		{"ECDSA-521", ecdsa521Priv, pkix.ECDSAWithSHA256},
		{"Ed25519", ed25519Priv, pkix.PureEd25519},
	}

	for _, test := range tests {
		template := CertificateRequest{
			Subject:            pkix.Name{}.AppendRDN(pkix.OidCommonName, "test.example.com").AppendRDN(pkix.OidOrganization, "Σ Acme Co"),
			SignatureAlgorithm: test.sigAlgo,
			San: &x509.SubjectAlternativeName{
				DNSNames:       []string{"test.example.com"},
				EmailAddresses: []string{"gopher@golang.org"},
				IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},
			},
		}

		derBytes, err := template.CreateCertificateRequest(test.priv)
		if err != nil {
			t.Errorf("%s: failed to create certificate request: %s", test.name, err)
			continue
		}

		out, err := ParseCertificateRequest(derBytes)
		if err != nil {
			t.Errorf("%s: failed to create certificate request: %s", test.name, err)
			continue
		}

		err = out.CheckSignature()
		if err != nil {
			t.Errorf("%s: failed to check certificate request signature: %s", test.name, err)
			continue
		}

		if len(out.Subject.CommonName) != len(template.Subject.CommonName) {
			t.Errorf("%s: output subject common name and template subject common name don't match", test.name)
		} else if len(out.Subject.Organization) != len(template.Subject.Organization) {
			t.Errorf("%s: output subject organisation and template subject organisation don't match", test.name)
		} else if out.San == nil {
			t.Errorf("%s: output SubjectAlternativeNames extension doesn't exist in cert", test.name)
		} else if len(out.San.DNSNames) != len(template.San.DNSNames) {
			t.Errorf("%s: output DNS names and template DNS names don't match", test.name)
		} else if len(out.San.EmailAddresses) != len(template.San.EmailAddresses) {
			t.Errorf("%s: output email addresses and template email addresses don't match", test.name)
		} else if len(out.San.IPAddresses) != len(template.San.IPAddresses) {
			t.Errorf("%s: output IP addresses and template IP addresses names don't match", test.name)
		}
	}
}

func marshalAndParseCSR(t *testing.T, template *CertificateRequest) *CertificateRequest {
	t.Helper()
	derBytes, err := template.CreateCertificateRequest(testPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	csr, err := ParseCertificateRequest(derBytes)
	if err != nil {
		t.Fatal(err)
	}

	return csr
}

func TestSANOtherNameDirectoryAndRegisterID(t *testing.T) {
	otherName := pkix.OtherName{}
	otherName.Set(asn1.UTF8String("FooString"), 1, 2, 3, 4, 5, 6)
	regID := pkix.RegisterID{}
	regID.Set(1, 2, 3, 4, 5, 7)
	name := pkix.Name{}.AppendRDN(pkix.OidCommonName, "utf8:testCN").AppendRDN(pkix.OidOrganization, "bmp:異體字")
	name2 := pkix.Name{}.AppendRDN(pkix.OidCommonName, asn1.UTF8String("testCN2")).AppendRDN(pkix.OidOrganizationalUnit, asn1.BMPString("異體字"))

	template := CertificateRequest{
		Subject: pkix.Name{}.AppendRDN(pkix.OidCommonName, "test.example.com"),
		San: &x509.SubjectAlternativeName{
			OtherNames:     []pkix.OtherName{otherName},
			RegisterIDs:    []pkix.RegisterID{regID},
			DirectoryNames: []pkix.Name{name, name2},
		},
	}

	csr := marshalAndParseCSR(t, &template)

	if csr.San == nil || len(csr.San.DirectoryNames) != 2 || len(csr.San.DirectoryNames[0].Names) != 2 || len(csr.San.DirectoryNames[1].Names) != 2 ||
		len(csr.San.DirectoryNames[0].CommonName) != 1 || len(csr.San.DirectoryNames[1].CommonName) != 1 {
		t.Errorf("DirectoryNames do not match.\n")
	} else {
		if csr.San.DirectoryNames[0].CommonName[0] != "testCN" ||
			len(csr.San.DirectoryNames[0].Organization) != 1 || csr.San.DirectoryNames[0].Organization[0] != "異體字" {
			t.Errorf("DirectoryNames 1 does not match.\n")
		}

		if !csr.San.DirectoryNames[0].Names[0].Type.Equal(pkix.OidCommonName) || csr.San.DirectoryNames[0].Names[0].Value != asn1.UTF8String("testCN") ||
			!csr.San.DirectoryNames[0].Names[1].Type.Equal(pkix.OidOrganization) || !reflect.DeepEqual(asn1.BMPString("異體字"), csr.San.DirectoryNames[0].Names[1].Value) {
			t.Errorf("DirectoryNames 1 does not match.\n")
		}

		if csr.San.DirectoryNames[1].CommonName[0] != "testCN2" ||
			len(csr.San.DirectoryNames[1].OrganizationalUnit) != 1 || csr.San.DirectoryNames[1].OrganizationalUnit[0] != "異體字" {
			t.Errorf("DirectoryNames 2 does not match.\n")
		}

		if !csr.San.DirectoryNames[1].Names[0].Type.Equal(pkix.OidCommonName) || csr.San.DirectoryNames[1].Names[0].Value != asn1.UTF8String("testCN2") ||
			!csr.San.DirectoryNames[1].Names[1].Type.Equal(pkix.OidOrganizationalUnit) || !reflect.DeepEqual(asn1.BMPString("異體字"), csr.San.DirectoryNames[1].Names[1].Value) {
			t.Errorf("DirectoryNames 2 does not match.\n")
		}
	}

	if len(csr.San.OtherNames) != 1 || !slices.Equal(csr.San.OtherNames[0].Value.Bytes, otherName.Value.Bytes) {
		t.Errorf("OtherName does not match\n")
	}

	if len(csr.San.RegisterIDs) != 1 || csr.San.RegisterIDs[0].String() != regID.String() {
		t.Errorf("RegisterID does not match.\n")
	}

}

func TestCertificateRequestRoundtripFields(t *testing.T) {
	urlA, err := url.Parse("https://example.com/_")
	if err != nil {
		t.Fatal(err)
	}
	urlB, err := url.Parse("https://example.org/_")
	if err != nil {
		t.Fatal(err)
	}
	in := &CertificateRequest{
		San: &x509.SubjectAlternativeName{
			DNSNames:       []string{"example.com", "example.org"},
			EmailAddresses: []string{"a@example.com", "b@example.com"},
			IPAddresses:    []net.IP{net.IPv4(192, 0, 2, 0), net.IPv6loopback},
			URIs:           []*url.URL{urlA, urlB},
		},
	}
	out := marshalAndParseCSR(t, in)

	if out.San == nil {
		t.Fatalf("Unexpected San: got %v, want %v", out.San, in.San)
	} else {
		if !slices.Equal(in.San.DNSNames, out.San.DNSNames) {
			t.Fatalf("Unexpected DNSNames: got %v, want %v", out.San.DNSNames, in.San.DNSNames)
		}
		if !slices.Equal(in.San.EmailAddresses, out.San.EmailAddresses) {
			t.Fatalf("Unexpected EmailAddresses: got %v, want %v", out.San.EmailAddresses, in.San.EmailAddresses)
		}
		if len(in.San.IPAddresses) != len(out.San.IPAddresses) ||
			!in.San.IPAddresses[0].Equal(out.San.IPAddresses[0]) ||
			!in.San.IPAddresses[1].Equal(out.San.IPAddresses[1]) {
			t.Fatalf("Unexpected IPAddresses: got %v, want %v", out.San.IPAddresses, in.San.IPAddresses)
		}
		if !reflect.DeepEqual(in.San.URIs, out.San.URIs) {
			t.Fatalf("Unexpected URIs: got %v, want %v", out.San.URIs, in.San.URIs)
		}
	}
}

func TestCertificateRequestOverrides(t *testing.T) {
	sanContents, err := x509.MarshalSANs(&x509.SubjectAlternativeName{DNSNames: []string{"foo.example.com"}})
	if err != nil {
		t.Fatal(err)
	}

	template := CertificateRequest{
		Subject: pkix.Name{}.AppendRDN(pkix.OidCommonName, "test.example.com").AppendRDN(pkix.OidOrganization, "Σ Acme Co"),
		San: &x509.SubjectAlternativeName{
			DNSNames: []string{"test.example.com"},
		},

		// An explicit extension should override the DNSNames from the
		// template.
		ExtraExtensions: []pkix.Extension{
			{
				Id:       x509.OidExtensionSubjectAltName,
				Value:    sanContents,
				Critical: true,
			},
		},
	}

	csr := marshalAndParseCSR(t, &template)

	if csr.San == nil || len(csr.San.DNSNames) != 1 || csr.San.DNSNames[0] != "foo.example.com" {
		t.Errorf("Extension did not override template. Got %v\n", csr.San)
	}

	if len(csr.Extensions) != 1 || !csr.Extensions[0].Id.Equal(x509.OidExtensionSubjectAltName) || !csr.Extensions[0].Critical {
		t.Errorf("SAN extension was not faithfully copied, got %#v", csr.Extensions)
	}

	otherName := pkix.OtherName{}
	otherName.Set(asn1.UTF8String("FooString"), 1, 2, 3, 4, 5, 6)
	regID := pkix.RegisterID{}
	regID.Set(1, 2, 3, 4, 5, 7)
	name := pkix.Name{}.AppendRDN(pkix.OidCommonName, "utf8:testCN")

	sanContents3, err := x509.MarshalSANs(&x509.SubjectAlternativeName{
		OtherNames:     []pkix.OtherName{otherName},
		RegisterIDs:    []pkix.RegisterID{regID},
		DirectoryNames: []pkix.Name{name},
	})
	if err != nil {
		t.Fatal(err)
	}

	template.ExtraExtensions = []pkix.Extension{
		{
			Id:    x509.OidExtensionSubjectAltName,
			Value: sanContents3,
		},
	}

	csr = marshalAndParseCSR(t, &template)

	if csr.San == nil || len(csr.San.OtherNames) != 1 && !slices.Equal(csr.San.OtherNames[0].Value.Bytes, otherName.Value.Bytes) {
		t.Errorf("OtherName does not match\n")
	}

	if csr.San == nil || len(csr.San.DirectoryNames) != 1 || len(csr.San.DirectoryNames[0].CommonName) != 1 || csr.San.DirectoryNames[0].CommonName[0] != name.CommonName[0] {
		t.Errorf("DirectoryNames does not match.\n")
	}

	if csr.San == nil || len(csr.San.RegisterIDs) != 1 && csr.San.RegisterIDs[0].String() != regID.String() {
		t.Errorf("RegisterID does not match.\n")
	}
}

func fromBase64(in string, t *testing.T) []byte {
	ret, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		t.Fatal("unable to decode base64")
	}
	return ret
}

func TestParseCertificateRequest(t *testing.T) {
	for _, csrBase64 := range csrBase64Array {
		csrBytes := fromBase64(csrBase64, t)
		csr, err := ParseCertificateRequest(csrBytes)
		if err != nil {
			t.Fatalf("failed to parse CSR: %s", err)
		}

		if csr.San == nil || len(csr.San.EmailAddresses) != 1 || csr.San.EmailAddresses[0] != "gopher@golang.org" {
			t.Errorf("incorrect email addresses found: %v", csr.San)
		}

		if csr.San == nil || len(csr.San.DNSNames) != 1 || csr.San.DNSNames[0] != "test.example.com" {
			t.Errorf("incorrect DNS names found: %v", csr.San)
		}

		if len(csr.Subject.Country) != 1 || csr.Subject.Country[0] != "AU" {
			t.Errorf("incorrect Subject name: %v", csr.Subject)
		}

		found := false
		for _, e := range csr.Extensions {
			if e.Id.Equal(x509.OidExtensionBasicConstraints) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("basic constraints extension not found in CSR")
		}
	}
}

func TestCriticalFlagInCSRRequestedExtensions(t *testing.T) {
	// This CSR contains an extension request where the extensions have a
	// critical flag in them. In the past we failed to handle this.
	const csrBase64 = "MIICrTCCAZUCAQIwMzEgMB4GA1UEAwwXU0NFUCBDQSBmb3IgRGV2ZWxlciBTcmwxDzANBgNVBAsMBjQzNTk3MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALFMAJ7Zy9YyfgbNlbUWAW0LalNRMPs7aXmLANsCpjhnw3lLlfDPaLeWyKh1nK5I5ojaJOW6KIOSAcJkDUe3rrE0wR0RVt3UxArqs0R/ND3u5Q+bDQY2X1HAFUHzUzcdm5JRAIA355v90teMckaWAIlkRQjDE22Lzc6NAl64KOd1rqOUNj8+PfX6fSo20jm94Pp1+a6mfk3G/RUWVuSm7owO5DZI/Fsi2ijdmb4NUar6K/bDKYTrDFkzcqAyMfP3TitUtBp19Mp3B1yAlHjlbp/r5fSSXfOGHZdgIvp0WkLuK2u5eQrX5l7HMB/5epgUs3HQxKY6ljhh5wAjDwz//LsCAwEAAaA1MDMGCSqGSIb3DQEJDjEmMCQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQEFBQADggEBAAMq3bxJSPQEgzLYR/yaVvgjCDrc3zUbIwdOis6Go06Q4RnjH5yRaSZAqZQTDsPurQcnz2I39VMGEiSkFJFavf4QHIZ7QFLkyXadMtALc87tm17Ej719SbHcBSSZayR9VYJUNXRLayI6HvyUrmqcMKh+iX3WY3ICr59/wlM0tYa8DYN4yzmOa2Onb29gy3YlaF5A2AKAMmk003cRT9gY26mjpv7d21czOSSeNyVIoZ04IR9ee71vWTMdv0hu/af5kSjQ+ZG5/Qgc0+mnECLz/1gtxt1srLYbtYQ/qAY8oX1DCSGFS61tN/vl+4cxGMD/VGcGzADRLRHSlVqy2Qgss6Q="

	csrBytes := fromBase64(csrBase64, t)
	csr, err := ParseCertificateRequest(csrBytes)
	if err != nil {
		t.Fatalf("failed to parse CSR: %s", err)
	}

	expected := []struct {
		Id    asn1.ObjectIdentifier
		Value []byte
	}{
		{x509.OidExtensionBasicConstraints, fromBase64("MAYBAf8CAQA=", t)},
		{x509.OidExtensionKeyUsage, fromBase64("AwIChA==", t)},
	}

	if n := len(csr.Extensions); n != len(expected) {
		t.Fatalf("expected to find %d extensions but found %d", len(expected), n)
	}

	for i, extension := range csr.Extensions {
		if !extension.Id.Equal(expected[i].Id) {
			t.Fatalf("extension #%d has unexpected type %v (expected %v)", i, extension.Id, expected[i].Id)
		}

		if !bytes.Equal(extension.Value, expected[i].Value) {
			t.Fatalf("extension #%d has unexpected contents %x (expected %x)", i, extension.Value, expected[i].Value)
		}
	}
}

const dupExtCSR = `-----BEGIN CERTIFICATE REQUEST-----
MIIBczCB3QIBADAPMQ0wCwYDVQQDEwR0ZXN0MIGfMA0GCSqGSIb3DQEBAQUAA4GN
ADCBiQKBgQC5PbxMGVJ8aLF9lq/EvGObXTRMB7ieiZL9N+DJZg1n/ECCnZLIvYrr
ZmmDV7YZsClgxKGfjJB0RQFFyZElFM9EfHEs8NJdidDKCRdIhDXQWRyhXKevHvdm
CQNKzUeoxvdHpU/uscSkw6BgUzPyLyTx9A6ye2ix94z8Y9hGOBO2DQIDAQABoCUw
IwYJKoZIhvcNAQkOMRYwFDAIBgIqAwQCBQAwCAYCKgMEAgUAMA0GCSqGSIb3DQEB
CwUAA4GBAHROEsE7URk1knXmBnQtIHwoq663vlMcX3Hes58pUy020rWP8QkocA+X
VF18/phg3p5ILlS4fcbbP2bEeV0pePo2k00FDPsJEKCBAX2LKxbU7Vp2OuV2HM2+
VLOVx0i+/Q7fikp3hbN1JwuMTU0v2KL/IKoUcZc02+5xiYrnOIt5
-----END CERTIFICATE REQUEST-----`

func TestDuplicateExtensionsCSR(t *testing.T) {
	b, _ := pem.Decode([]byte(dupExtCSR))
	if b == nil {
		t.Fatalf("couldn't decode test CSR")
	}
	_, err := ParseCertificateRequest(b.Bytes)
	if err == nil {
		t.Fatal("ParseCertificateRequest should fail when parsing CSR with duplicate extensions")
	}
}

const dupAttCSR = `-----BEGIN CERTIFICATE REQUEST-----
MIIBbDCB1gIBADAPMQ0wCwYDVQQDEwR0ZXN0MIGfMA0GCSqGSIb3DQEBAQUAA4GN
ADCBiQKBgQCj5Po3PKO/JNuxr+B+WNfMIzqqYztdlv+mTQhT0jOR5rTkUvxeeHH8
YclryES2dOISjaUOTmOAr5GQIIdQl4Ql33Cp7ZR/VWcRn+qvTak0Yow+xVsDo0n4
7IcvvP6CJ7FRoYBUakVczeXLxCjLwdyK16VGJM06eRzDLykPxpPwLQIDAQABoB4w
DQYCKgMxBwwFdGVzdDEwDQYCKgMxBwwFdGVzdDIwDQYJKoZIhvcNAQELBQADgYEA
UJ8hsHxtnIeqb2ufHnQFJO+wEJhx2Uxm/BTuzHOeffuQkwATez4skZ7SlX9exgb7
6jRMRilqb4F7f8w+uDoqxRrA9zc8mwY16zPsyBhRet+ZGbj/ilgvGmtZ21qZZ/FU
0pJFJIVLM3l49Onr5uIt5+hCWKwHlgE0nGpjKLR3cMg=
-----END CERTIFICATE REQUEST-----`

func TestDuplicateAttributesCSR(t *testing.T) {
	b, _ := pem.Decode([]byte(dupAttCSR))
	if b == nil {
		t.Fatalf("couldn't decode test CSR")
	}
	_, err := ParseCertificateRequest(b.Bytes)
	if err != nil {
		t.Fatal("ParseCertificateRequest should succeed when parsing CSR with duplicate attributes")
	}
}
