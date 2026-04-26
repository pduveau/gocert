package crl

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/pkcs8"
	"github.com/pduveau/gocert/pkix"
	"github.com/pduveau/gocert/x509"
)

func TestCreateRevocationList(t *testing.T) {
	ec256Priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA P256 key: %s", err)
	}
	_, ed25519Priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %s", err)
	}

	// Generation command:
	// openssl req -x509 -newkey rsa -keyout key.pem -out cert.pem -days 365 -nodes -subj '/C=US/ST=California/L=San Francisco/O=Internet Widgets, Inc./OU=WWW/CN=Root/emailAddress=admin@example.com' -sha256 -addext basicConstraints=CA:TRUE -addext "keyUsage = digitalSignature, keyEncipherment, dataEncipherment, cRLSign, keyCertSign" -utf8
	utf8CAStr := "MIIEITCCAwmgAwIBAgIUXHXy7NdtDv+ClaHvIvlwCYiI4a4wDQYJKoZIhvcNAQELBQAwgZoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMR8wHQYDVQQKDBZJbnRlcm5ldCBXaWRnZXRzLCBJbmMuMQwwCgYDVQQLDANXV1cxDTALBgNVBAMMBFJvb3QxIDAeBgkqhkiG9w0BCQEWEWFkbWluQGV4YW1wbGUuY29tMB4XDTIyMDcwODE1MzgyMFoXDTIzMDcwODE1MzgyMFowgZoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMR8wHQYDVQQKDBZJbnRlcm5ldCBXaWRnZXRzLCBJbmMuMQwwCgYDVQQLDANXV1cxDTALBgNVBAMMBFJvb3QxIDAeBgkqhkiG9w0BCQEWEWFkbWluQGV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmXvp0WNjsZzySWT7Ce5zewQNKq8ujeZGphJ44Vdrwut/b6TcC4iYENds5+7/3PYwBllp3K5TRpCcafSxdhJsvA7/zWlHHNRcJhJLNt9qsKWP6ukI2Iw6OmFMg6kJQ8f67RXkT8HR3v0UqE+lWrA0g+oRuj4erLtfOtSpnl4nsE/Rs2qxbELFWAf7F5qMqH4dUyveWKrNT8eI6YQN+wBg0MAjoKRvDJnBhuo+IvvXX8Aq1QWUcBGPK3or/Ehxy5f/gEmSUXyEU1Ht/vATt2op+eRaEEpBdGRvO+DrKjlcQV2XMN18A9LAX6hCzH43sGye87dj7RZ9yj+waOYNaM7kFQIDAQABo10wWzAdBgNVHQ4EFgQUtbSlrW4hGL2kNjviM6wcCRwvOEEwHwYDVR0jBBgwFoAUtbSlrW4hGL2kNjviM6wcCRwvOEEwDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCAbYwDQYJKoZIhvcNAQELBQADggEBAAko82YNNI2n/45L3ya21vufP6nZihIOIxgcRPUMX+IDJZk16qsFdcLgH3KAP8uiVLn8sULuCj35HpViR4IcAk2d+DqfG11l8kY+e5P7nYsViRfy0AatF59/sYlWf+3RdmPXfL70x4mE9OqlMdDm0kR2obps8rng83VLDNvj3R5sBnQwdw6LKLGzaE+RiCTmkH0+P6vnbOJ33su9+9al1+HvJUg3UM1Xq5Bw7TE8DQTetMV3c2Q35RQaJB9pQ4blJOnW9hfnt8yQzU6TU1bU4mRctTm1o1f8btPqUpi+/blhi5MUJK0/myj1XD00pmyfp8QAFl1EfqmTMIBMLg633A0="
	utf8CABytes, _ := base64.StdEncoding.DecodeString(utf8CAStr)
	utf8CA, _ := x509.ParseCertificate(utf8CABytes)

	utf8KeyStr := "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCZe+nRY2OxnPJJZPsJ7nN7BA0qry6N5kamEnjhV2vC639vpNwLiJgQ12zn7v/c9jAGWWncrlNGkJxp9LF2Emy8Dv/NaUcc1FwmEks232qwpY/q6QjYjDo6YUyDqQlDx/rtFeRPwdHe/RSoT6VasDSD6hG6Ph6su1861KmeXiewT9GzarFsQsVYB/sXmoyofh1TK95Yqs1Px4jphA37AGDQwCOgpG8MmcGG6j4i+9dfwCrVBZRwEY8reiv8SHHLl/+ASZJRfIRTUe3+8BO3ain55FoQSkF0ZG874OsqOVxBXZcw3XwD0sBfqELMfjewbJ7zt2PtFn3KP7Bo5g1ozuQVAgMBAAECggEAIscjKiD9PAe2Fs9c2tk/LYazfRKI1/pv072nylfGwToffCq8+ZgP7PEDamKLc4QNScME685MbFbkOlYJyBlQriQv7lmGlY/A+Zd3l410XWaGf9IiAP91Sjk13zd0M/micApf23qtlXt/LMwvSadXnvRw4+SjirxCTdBWRt5K2/ZAN550v7bHFk1EZc3UBF6sOoNsjQWh9Ek79UmQYJBPiZDBHO7O2fh2GSIbUutTma+Tb2i1QUZzg+AG3cseF3p1i3uhNrCh+p+01bJSzGTQsRod2xpD1tpWwR3kIftCOmD1XnhpaBQi7PXjEuNbfucaftnoYj2ShDdmgD5RkkbTAQKBgQC8Ghu5MQ/yIeqXg9IpcSxuWtUEAEfK33/cC/IvuntgbNEnWQm5Lif4D6a9zjkxiCS+9HhrUu5U2EV8NxOyaqmtub3Np1Z5mPuI9oiZ119bjUJd4X+jKOTaePWvOv/rL/pTHYqzXohVMrXy+DaTIq4lOcv3n72SuhuTcKU95rhKtQKBgQDQ4t+HsRZd5fJzoCgRQhlNK3EbXQDv2zXqMW3GfpF7GaDP18I530inRURSJa++rvi7/MCFg/TXVS3QC4HXtbzTYTqhE+VHzSr+/OcsqpLE8b0jKBDv/SBkz811PUJDs3LsX31DT3K0zUpMpNSd/5SYTyJKef9L6mxmwlC1S2Yv4QKBgQC57SiYDdnQIRwrtZ2nXvlm/xttAAX2jqJoU9qIuNA4yHaYaRcGVowlUvsiw9OelQ6VPTpGA0wWy0src5lhkrKzSFRHEe+U89U1VVJCljLoYKFIAJvUH5jOJh/am/vYca0COMIfeAJUDHLyfcwb9XyiyRVGZzvP62tUelSq8gIZvQKBgCAHeaDzzWsudCO4ngwvZ3PGwnwgoaElqrmzRJLYG3SVtGvKOJTpINnNLDGwZ6dEaw1gLyEJ38QY4oJxEULDMiXzVasXQuPkmMAqhUP7D7A1JPw8C4TQ+mOa3XUppHx/CpMl/S4SA5OnmsnvyE5Fv0IveCGVXUkFtAN5rihuXEfhAoGANUkuGU3A0Upk2mzv0JTGP4H95JFG93cqnyPNrYs30M6RkZNgTW27yyr+Nhs4/cMdrg1AYTB0+6ItQWSDmYLs7JEbBE/8L8fdD1irIcygjIHE9nJh96TgZCt61kVGLE8758lOdmoB2rZOpGwi16QIhdQb+IyozYqfX+lQUojL/W0="
	utf8KeyBytes, _ := base64.StdEncoding.DecodeString(utf8KeyStr)
	utf8KeyRaw, _ := pkcs8.ParsePKCS8PrivateKey(utf8KeyBytes)
	utf8Key := utf8KeyRaw.(crypto.Signer)

	tests := []struct {
		name          string
		key           crypto.Signer
		issuer        *x509.Certificate
		template      *RevocationList
		expectedError string
	}{
		{
			name:          "nil template",
			key:           ec256Priv,
			issuer:        nil,
			template:      nil,
			expectedError: "template can not be nil",
		},
		{
			name:          "nil issuer",
			key:           ec256Priv,
			issuer:        nil,
			template:      &RevocationList{},
			expectedError: "issuer can not be nil",
		},
		{
			name: "issuer doesn't have crlSign key usage bit set",
			key:  ec256Priv,
			issuer: &x509.Certificate{
				KeyUsage: x509.KeyUsageCertSign,
			},
			template:      &RevocationList{},
			expectedError: "issuer must have the crlSign key usage bit set",
		},
		{
			name: "issuer missing SubjectKeyId",
			key:  ec256Priv,
			issuer: &x509.Certificate{
				KeyUsage: x509.KeyUsageCRLSign,
			},
			template:      &RevocationList{},
			expectedError: "issuer certificate doesn't contain a subject key identifier",
		},
		{
			name: "nextUpdate before thisUpdate",
			key:  ec256Priv,
			issuer: &x509.Certificate{
				KeyUsage:     x509.KeyUsageCRLSign,
				Subject:      pkix.Name{}.AppendRDN(pkix.OidCommonName, "testing"),
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				ThisUpdate: time.Time{}.Add(time.Hour),
				NextUpdate: time.Time{},
			},
			expectedError: "template.ThisUpdate is after template.NextUpdate",
		},
		{
			name: "nil Number",
			key:  ec256Priv,
			issuer: &x509.Certificate{
				KeyUsage:     x509.KeyUsageCRLSign,
				Subject:      pkix.Name{}.AppendRDN(pkix.OidCommonName, "testing"),
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
			expectedError: "Number field can not be nil",
		},
		{
			name: "long Number",
			key:  ec256Priv,
			issuer: &x509.Certificate{
				KeyUsage:     x509.KeyUsageCRLSign,
				Subject:      pkix.Name{}.AppendRDN(pkix.OidCommonName, "testing"),
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
				Number:     big.NewInt(0).SetBytes(append([]byte{1}, make([]byte, 20)...)),
			},
			expectedError: "CRL number exceeds 20 octets",
		},
		{
			name: "long Number (20 bytes, MSB set)",
			key:  ec256Priv,
			issuer: &x509.Certificate{
				KeyUsage:     x509.KeyUsageCRLSign,
				Subject:      pkix.Name{}.AppendRDN(pkix.OidCommonName, "testing"),
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
				Number:     big.NewInt(0).SetBytes(append([]byte{255}, make([]byte, 19)...)),
			},
			expectedError: "CRL number exceeds 20 octets",
		},
		{
			name: "valid, reason code",
			key:  ec256Priv,
			issuer: &x509.Certificate{
				KeyUsage:     x509.KeyUsageCRLSign,
				Subject:      pkix.Name{}.AppendRDN(pkix.OidCommonName, "testing"),
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				RevokedCertificateEntries: []RevocationListEntry{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
						ReasonCode:     1,
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, extra entry extension",
			key:  ec256Priv,
			issuer: &x509.Certificate{
				KeyUsage:     x509.KeyUsageCRLSign,
				Subject:      pkix.Name{}.AppendRDN(pkix.OidCommonName, "testing"),
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				RevokedCertificateEntries: []RevocationListEntry{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
						ExtraExtensions: []pkix.Extension{
							{
								Id:    asn1.ObjectIdentifier{2, 5, 29, 99},
								Value: []byte{5, 0},
							},
						},
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, Ed25519 key",
			key:  ed25519Priv,
			issuer: &x509.Certificate{
				KeyUsage:     x509.KeyUsageCRLSign,
				Subject:      pkix.Name{}.AppendRDN(pkix.OidCommonName, "testing"),
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				RevokedCertificateEntries: []RevocationListEntry{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, non-default signature algorithm",
			key:  ec256Priv,
			issuer: &x509.Certificate{
				KeyUsage:     x509.KeyUsageCRLSign,
				Subject:      pkix.Name{}.AppendRDN(pkix.OidCommonName, "testing"),
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				SignatureAlgorithm: pkix.ECDSAWithSHA512,
				RevokedCertificateEntries: []RevocationListEntry{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, extra extension",
			key:  ec256Priv,
			issuer: &x509.Certificate{
				KeyUsage:     x509.KeyUsageCRLSign,
				Subject:      pkix.Name{}.AppendRDN(pkix.OidCommonName, "testing"),
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				RevokedCertificateEntries: []RevocationListEntry{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
				ExtraExtensions: []pkix.Extension{
					{
						Id:    asn1.ObjectIdentifier{2, 5, 29, 99},
						Value: []byte{5, 0},
					},
				},
			},
		},
		{
			name: "valid, empty list",
			key:  ec256Priv,
			issuer: &x509.Certificate{
				KeyUsage:     x509.KeyUsageCRLSign,
				Subject:      pkix.Name{}.AppendRDN(pkix.OidCommonName, "testing"),
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name:   "valid CA with utf8 Subject fields including Email, empty list",
			key:    utf8Key,
			issuer: utf8CA,
			template: &RevocationList{
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			crl, err := CreateRevocationList(tc.template, tc.issuer, tc.key)
			if err != nil && tc.expectedError == "" {
				t.Fatalf("CreateRevocationList failed unexpectedly: %s", err)
			} else if err != nil && !strings.Contains(err.Error(), tc.expectedError) {
				t.Fatalf("CreateRevocationList failed unexpectedly, wanted: %s, got: %s", tc.expectedError, err)
			} else if err == nil && tc.expectedError != "" {
				t.Fatalf("CreateRevocationList didn't fail, expected: %s", tc.expectedError)
			}
			if tc.expectedError != "" {
				return
			}

			parsedCRL, err := ParseRevocationList(crl)
			if err != nil {
				t.Fatalf("Failed to parse generated CRL: %s", err)
			}

			if tc.template.SignatureAlgorithm != pkix.UnknownSignatureAlgorithm &&
				parsedCRL.SignatureAlgorithm != tc.template.SignatureAlgorithm {
				t.Fatalf("SignatureAlgorithm mismatch: got %v; want %v.", parsedCRL.SignatureAlgorithm,
					tc.template.SignatureAlgorithm)
			}

			if len(parsedCRL.RevokedCertificateEntries) != len(tc.template.RevokedCertificateEntries) {
				t.Fatalf("RevokedCertificateEntries length mismatch: got %d; want %d.",
					len(parsedCRL.RevokedCertificateEntries),
					len(tc.template.RevokedCertificateEntries))
			}
			for i, rce := range parsedCRL.RevokedCertificateEntries {
				expected := tc.template.RevokedCertificateEntries[i]
				if rce.SerialNumber.Cmp(expected.SerialNumber) != 0 {
					t.Fatalf("RevocationListEntry serial mismatch: got %d; want %d.",
						rce.SerialNumber, expected.SerialNumber)
				}
				if !rce.RevocationTime.Equal(expected.RevocationTime) {
					t.Fatalf("RevocationListEntry revocation time mismatch: got %v; want %v.",
						rce.RevocationTime, expected.RevocationTime)
				}
				if rce.ReasonCode != expected.ReasonCode {
					t.Fatalf("RevocationListEntry reason code mismatch: got %d; want %d.",
						rce.ReasonCode, expected.ReasonCode)
				}
			}

			if len(parsedCRL.Extensions) != 2+len(tc.template.ExtraExtensions) {
				t.Fatalf("Generated CRL has wrong number of extensions, wanted: %d, got: %d", 2+len(tc.template.ExtraExtensions), len(parsedCRL.Extensions))
			}

			expectedAKI, err := tc.issuer.MarshelAki()
			if err != nil {
				t.Fatalf("asn1.Marshal failed: %s", err)
			}
			akiExt := pkix.Extension{
				Id:    x509.OidExtensionAuthorityKeyId,
				Value: expectedAKI,
			}
			if !reflect.DeepEqual(parsedCRL.Extensions[0], akiExt) {
				t.Fatalf("Unexpected first extension: got %v, want %v",
					parsedCRL.Extensions[0], akiExt)
			}
			expectedNum, err := asn1.Marshal(tc.template.Number)
			if err != nil {
				t.Fatalf("asn1.Marshal failed: %s", err)
			}
			crlExt := pkix.Extension{
				Id:    oidExtensionCRLNumber,
				Value: expectedNum,
			}
			if !reflect.DeepEqual(parsedCRL.Extensions[1], crlExt) {
				t.Fatalf("Unexpected second extension: got %v, want %v",
					parsedCRL.Extensions[1], crlExt)
			}

			// With Go 1.19's updated RevocationList, we can now directly compare
			// the RawSubject of the certificate to RawIssuer on the parsed CRL.
			// However, this doesn't work with our hacked issuers above (that
			// aren't parsed from a proper DER bundle but are instead manually
			// constructed). Prefer RawSubject when it is set.
			if len(tc.issuer.RawSubject) > 0 {
				issuerSubj, err := tc.issuer.SubjectBytes()
				if err != nil {
					t.Fatalf("failed to get issuer subject: %s", err)
				}
				if !bytes.Equal(issuerSubj, parsedCRL.RawIssuer) {
					t.Fatalf("Unexpected issuer subject; wanted: %v, got: %v", hex.EncodeToString(issuerSubj), hex.EncodeToString(parsedCRL.RawIssuer))
				}
			} else {
				// When we hack our custom Subject in the test cases above,
				// we don't set the additional fields (such as Names) in the
				// hacked issuer. Round-trip a parsing of pkix.Name so that
				// we add these missing fields for the comparison.
				issuerRDN := tc.issuer.Subject.ToRDNSequence()
				var caIssuer pkix.Name
				caIssuer.FillFromRDNSequence(&issuerRDN)
				if !reflect.DeepEqual(caIssuer, parsedCRL.Issuer) {
					t.Fatalf("Expected issuer.Subject, parsedCRL.Issuer to be the same; wanted: %#v, got: %#v", caIssuer, parsedCRL.Issuer)
				}
			}

			if len(parsedCRL.Extensions[2:]) == 0 && len(tc.template.ExtraExtensions) == 0 {
				// If we don't have anything to check return early so we don't
				// hit a [] != nil false positive below.
				return
			}
			if !reflect.DeepEqual(parsedCRL.Extensions[2:], tc.template.ExtraExtensions) {
				t.Fatalf("Extensions mismatch: got %v; want %v.",
					parsedCRL.Extensions[2:], tc.template.ExtraExtensions)
			}

			if tc.template.Number != nil && parsedCRL.Number == nil {
				t.Fatalf("Generated CRL missing Number: got nil, want %s",
					tc.template.Number.String())
			}
			if tc.template.Number != nil && tc.template.Number.Cmp(parsedCRL.Number) != 0 {
				t.Fatalf("Generated CRL has wrong Number: got %s, want %s",
					parsedCRL.Number.String(), tc.template.Number.String())
			}
			if !bytes.Equal(parsedCRL.AuthorityKeyId, tc.issuer.SubjectKeyId) {
				t.Fatalf("Generated CRL has wrong AuthorityKeyId: got %x, want %x",
					parsedCRL.AuthorityKeyId, tc.issuer.SubjectKeyId)
			}
		})
	}
}

func TestRevocationListCheckSignatureFrom(t *testing.T) {
	goodKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %s", err)
	}
	badKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %s", err)
	}
	tests := []struct {
		name   string
		issuer *x509.Certificate
		err    string
	}{
		{
			name: "valid",
			issuer: &x509.Certificate{
				Version:               3,
				BasicConstraintsValid: true,
				IsCA:                  true,
				PublicKeyAlgorithm:    pkix.ECDSA,
				PublicKey:             goodKey.Public(),
			},
		},
		{
			name: "valid, key usage set",
			issuer: &x509.Certificate{
				Version:               3,
				BasicConstraintsValid: true,
				IsCA:                  true,
				PublicKeyAlgorithm:    pkix.ECDSA,
				PublicKey:             goodKey.Public(),
				KeyUsage:              x509.KeyUsageCRLSign,
			},
		},
		{
			name: "invalid issuer, wrong key usage",
			issuer: &x509.Certificate{
				Version:               3,
				BasicConstraintsValid: true,
				IsCA:                  true,
				PublicKeyAlgorithm:    pkix.ECDSA,
				PublicKey:             goodKey.Public(),
				KeyUsage:              x509.KeyUsageCertSign,
			},
			err: "invalid signature: parent certificate cannot sign this kind of certificate",
		},
		{
			name: "invalid issuer, no basic constraints/ca",
			issuer: &x509.Certificate{
				Version:            3,
				PublicKeyAlgorithm: pkix.ECDSA,
				PublicKey:          goodKey.Public(),
			},
			err: "invalid signature: parent certificate cannot sign this kind of certificate",
		},
		{
			name: "invalid issuer, unsupported public key type",
			issuer: &x509.Certificate{
				Version:               3,
				BasicConstraintsValid: true,
				IsCA:                  true,
				PublicKeyAlgorithm:    pkix.UnknownPublicKeyAlgorithm,
				PublicKey:             goodKey.Public(),
			},
			err: "unsuported algorithm",
		},
		{
			name: "wrong key",
			issuer: &x509.Certificate{
				Version:               3,
				BasicConstraintsValid: true,
				IsCA:                  true,
				PublicKeyAlgorithm:    pkix.ECDSA,
				PublicKey:             badKey.Public(),
			},
			err: "ECDSA verification failure",
		},
	}

	crlIssuer := &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		PublicKeyAlgorithm:    pkix.ECDSA,
		PublicKey:             goodKey.Public(),
		KeyUsage:              x509.KeyUsageCRLSign,
		SubjectKeyId:          []byte{1, 2, 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			crlDER, err := CreateRevocationList(&RevocationList{Number: big.NewInt(1)}, crlIssuer, goodKey)
			if err != nil {
				t.Fatalf("failed to generate CRL: %s", err)
			}
			crl, err := ParseRevocationList(crlDER)
			if err != nil {
				t.Fatalf("failed to parse test CRL: %s", err)
			}
			err = crl.CheckSignatureFrom(tc.issuer)
			if err != nil && !strings.Contains(err.Error(), tc.err) {
				t.Errorf("unexpected error: got %s, want %s", err, tc.err)
			} else if err == nil && tc.err != "" {
				t.Errorf("CheckSignatureFrom did not fail: want %s", tc.err)
			}
		})
	}
}

const derCRLBase64 = "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"

func TestParseRevocationList(t *testing.T) {
	derBytes, err := base64.StdEncoding.DecodeString(derCRLBase64)
	if err != nil {
		t.Errorf("error decoding: %s", err)
		return
	}
	certList, err := ParseRevocationList(derBytes)
	if err != nil {
		t.Errorf("error parsing: %s", err)
		return
	}
	numCerts := len(certList.RevokedCertificateEntries)
	expected := 88
	if numCerts != expected {
		t.Errorf("bad number of revoked certificates. got: %d want: %d", numCerts, expected)
	}
}
