package pkix_test

import (
	"encoding/base64"
	"reflect"
	"testing"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/pkix"
	"github.com/pduveau/gocert/x509"
)

var certBytes = "MIIE0jCCA7qgAwIBAgIQWcvS+TTB3GwCAAAAAGEAWzANBgkqhkiG9w0BAQsFADBCMQswCQYD" +
	"VQQGEwJVUzEeMBwGA1UEChMVR29vZ2xlIFRydXN0IFNlcnZpY2VzMRMwEQYDVQQDEwpHVFMg" +
	"Q0EgMU8xMB4XDTIwMDQwMTEyNTg1NloXDTIwMDYyNDEyNTg1NlowaTELMAkGA1UEBhMCVVMx" +
	"EzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcxEzARBgNVBAoT" +
	"Ckdvb2dsZSBMTEMxGDAWBgNVBAMTD21haWwuZ29vZ2xlLmNvbTBZMBMGByqGSM49AgEGCCqG" +
	"SM49AwEHA0IABO+dYiPnkFl+cZVf6mrWeNp0RhQcJSBGH+sEJxjvc+cYlW3QJCnm57qlpFdd" +
	"pz3MPyVejvXQdM6iI1mEWP4C2OujggJmMIICYjAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAww" +
	"CgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUI6pZhnQ/lQgmPDwSKR2A54G7" +
	"AS4wHwYDVR0jBBgwFoAUmNH4bhDrz5vsYJ8YkBug630J/SswZAYIKwYBBQUHAQEEWDBWMCcG" +
	"CCsGAQUFBzABhhtodHRwOi8vb2NzcC5wa2kuZ29vZy9ndHMxbzEwKwYIKwYBBQUHMAKGH2h0" +
	"dHA6Ly9wa2kuZ29vZy9nc3IyL0dUUzFPMS5jcnQwLAYDVR0RBCUwI4IPbWFpbC5nb29nbGUu" +
	"Y29tghBpbmJveC5nb29nbGUuY29tMCEGA1UdIAQaMBgwCAYGZ4EMAQICMAwGCisGAQQB1nkC" +
	"BQMwLwYDVR0fBCgwJjAkoCKgIIYeaHR0cDovL2NybC5wa2kuZ29vZy9HVFMxTzEuY3JsMIIB" +
	"AwYKKwYBBAHWeQIEAgSB9ASB8QDvAHYAsh4FzIuizYogTodm+Su5iiUgZ2va+nDnsklTLe+L" +
	"kF4AAAFxNgmxKgAABAMARzBFAiEA12/OHdTGXQ3qHHC3NvYCyB8aEz/+ZFOLCAI7lhqj28sC" +
	"IG2/7Yz2zK6S6ai+dH7cTMZmoFGo39gtaTqtZAqEQX7nAHUAXqdz+d9WwOe1Nkh90EngMnqR" +
	"mgyEoRIShBh1loFxRVgAAAFxNgmxTAAABAMARjBEAiA7PNq+MFfv6O9mBkxFViS2TfU66yRB" +
	"/njcebWglLQjZQIgOyRKhxlEizncFRml7yn4Bg48ktXKGjo+uiw6zXEINb0wDQYJKoZIhvcN" +
	"AQELBQADggEBADM2Rh306Q10PScsolYMxH1B/K4Nb2WICvpY0yDPJFdnGjqCYym196TjiEvs" +
	"R6etfeHdyzlZj6nh82B4TVyHjiWM02dQgPalOuWQcuSy0OvLh7F1E7CeHzKlczdFPBTOTdM1" +
	"RDTxlvw1bAqc0zueM8QIAyEy3opd7FxAcGQd5WRIJhzLBL+dbbMOW/LTeW7cm/Xzq8cgCybN" +
	"BSZAvhjseJ1L29OlCTZL97IfnX0IlFQzWuvvHy7V2B0E3DHlzM0kjwkkCKDUUp/wajv2NZKC" +
	"TkhEyERacZRKc9U0ADxwsAzHrdz5+5zfD2usEV/MQ5V6d8swLXs+ko0X6swrd4YCiB8wggRK" +
	"MIIDMqADAgECAg0B47SaoY2KqYElaVC4MA0GCSqGSIb3DQEBCwUAMEwxIDAeBgNVBAsTF0ds" +
	"b2JhbFNpZ24gUm9vdCBDQSAtIFIyMRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpH" +
	"bG9iYWxTaWduMB4XDTE3MDYxNTAwMDA0MloXDTIxMTIxNTAwMDA0MlowQjELMAkGA1UEBhMC" +
	"VVMxHjAcBgNVBAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczETMBEGA1UEAxMKR1RTIENBIDFP" +
	"MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANAYz0XUi83TnORA73603WkhG8nP" +
	"PI5MdbkPMRmEPZ48Ke9QDRCTbwWAgJ8qoL0SSwLhPZ9YFiT+MJ8LdHdVkx1L903hkoIQ9lGs" +
	"DMOyIpQPNGuYEEnnC52DOd0gxhwt79EYYWXnI4MgqCMS/9Ikf9Qv50RqW03XUGawr55CYwX7" +
	"4BzEY2Gvn2oz/2KXvUjZ03wUZ9x13C5p6PhteGnQtxAFuPExwjsk/RozdPgj4OxrGYoWxuPN" +
	"pM0L27OkWWA4iDutHbnGjKdTG/y82aSrvN08YdeTFZjugb2P4mRHIEAGTtesl+i5wFkSoUkl" +
	"I+TtcDQspbRjfPmjPYPRzW0krAcCAwEAAaOCATMwggEvMA4GA1UdDwEB/wQEAwIBhjAdBgNV" +
	"HSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4E" +
	"FgQUmNH4bhDrz5vsYJ8YkBug630J/SswHwYDVR0jBBgwFoAUm+IHV2ccHsBqBt5ZtJot39wZ" +
	"hi4wNQYIKwYBBQUHAQEEKTAnMCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC5wa2kuZ29vZy9n" +
	"c3IyMDIGA1UdHwQrMCkwJ6AloCOGIWh0dHA6Ly9jcmwucGtpLmdvb2cvZ3NyMi9nc3IyLmNy" +
	"bDA/BgNVHSAEODA2MDQGBmeBDAECAjAqMCgGCCsGAQUFBwIBFhxodHRwczovL3BraS5nb29n" +
	"L3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBCwUAA4IBAQAagD42efvzLqlGN31eVBY1rsdOCJn+" +
	"vdE0aSZSZgc9CrpJy2L08RqO/BFPaJZMdCvTZ96yo6oFjYRNTCBlD6WW2g0W+Gw7228EI4hr" +
	"OmzBYL1on3GO7i1YNAfw1VTphln9e14NIZT1jMmo+NjyrcwPGvOap6kEJ/mjybD/AnhrYbrH" +
	"NSvoVvpPwxwM7bY8tEvq7czhPOzcDYzWPpvKQliLzBYhF0C8otZm79rEFVvNiaqbCSbnMtIN" +
	"bmcgAlsQsJAJnAwfnq3YO+qh/GzoEFwIUhlRKnG7rHq13RXtK8kIKiyKtKYhq2P/11JJUNCJ" +
	"t63yr/tQri/hlQ3zRq2dnPXK"

func TestPKIXNameString(t *testing.T) {
	der, err := base64.StdEncoding.DecodeString(certBytes)
	if err != nil {
		t.Fatal(err)
	}
	certs, err := x509.ParseCertificates(der)
	if err != nil {
		t.Fatal(err)
	}

	// Check that parsed non-standard attributes are printed.
	rdns := pkix.Name{}.AppendRDN(pkix.OidLocality, "Gophertown").AppendRDN(asn1.ObjectIdentifier{1, 2, 3, 4, 5}, "golang.org").ToRDNSequence()
	nn := pkix.Name{}
	nn.FillFromRDNSequence(&rdns)

	// Check that zero-length non-nil ExtraNames hide Names.
	extraNotNil := pkix.Name{
		Locality: []string{"Gophertown"},
		Names: []pkix.AttributeTypeAndValue{
			{Type: pkix.OidLocality, Value: "Gophertown"},
			{Type: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Value: "golang.org"},
		},
	}

	tests := []struct {
		dn   pkix.Name
		want string
	}{
		{nn, "L=Gophertown,1.2.3.4.5=#130a676f6c616e672e6f7267"},
		{extraNotNil, "L=Gophertown,1.2.3.4.5=#130a676f6c616e672e6f7267"},
		{pkix.Name{}.AppendRDN(pkix.OidCommonName, "Steve Kille").
			AppendRDN(pkix.OidOrganizationalUnit, "RFCs").
			AppendRDN(pkix.OidOrganization, "Isode Limited").
			AppendRDN(pkix.OidPostalCode, "TW9 1DT").
			AppendRDN(pkix.OidStreetAddress, "The Square").
			AppendRDN(pkix.OidLocality, "Richmond").
			AppendRDN(pkix.OidProvince, "Surrey").
			AppendRDN(pkix.OidCountry, "GB"),
			"CN=Steve Kille,OU=RFCs,O=Isode Limited,POSTALCODE=TW9 1DT,STREET=The Square,L=Richmond,ST=Surrey,C=GB"},
		{certs[0].Subject,
			"C=US,ST=California,L=Mountain View,O=Google LLC,CN=mail.google.com"},
		{pkix.Name{}.AppendRDN(pkix.OidOrganization, "#Google, Inc. \n-> 'Alphabet\" ").
			AppendRDN(pkix.OidCountry, "US"),
			"O=\\#Google\\, Inc. \n-\\> 'Alphabet\\\"\\ ,C=US"},
	}

	for i, test := range tests {
		if got := test.dn.String(); got != test.want {
			t.Errorf("#%d: String() = \n%s\n, want \n%s", i, got, test.want)
		}
	}
}

var testsRDNStrings = []struct {
	seq  pkix.RDNSequence
	want string
}{
	{
		seq: pkix.RDNSequence{
			pkix.RelativeDistinguishedNameSET{
				pkix.AttributeTypeAndValue{Type: pkix.OidCountry, Value: "US"},
			},
			pkix.RelativeDistinguishedNameSET{
				pkix.AttributeTypeAndValue{Type: pkix.OidOrganization, Value: "Widget Inc."},
			},
			pkix.RelativeDistinguishedNameSET{
				pkix.AttributeTypeAndValue{Type: pkix.OidOrganizationalUnit, Value: "Sales"},
				pkix.AttributeTypeAndValue{Type: pkix.OidCommonName, Value: "J. Smith"},
			},
		},
		want: "C=US,O=Widget Inc.,OU=Sales+CN=J. Smith",
	},
	{
		seq: pkix.RDNSequence{
			pkix.RelativeDistinguishedNameSET{
				pkix.AttributeTypeAndValue{Type: pkix.OidCommonName, Value: "J. Smith"},
			},
			pkix.RelativeDistinguishedNameSET{
				pkix.AttributeTypeAndValue{Type: pkix.OidOrganizationalUnit, Value: "Sales"},
			},
			pkix.RelativeDistinguishedNameSET{
				pkix.AttributeTypeAndValue{Type: pkix.OidOrganization, Value: "Widget Inc."},
			},
			pkix.RelativeDistinguishedNameSET{
				pkix.AttributeTypeAndValue{Type: pkix.OidCountry, Value: "US"},
			},
		},
		want: "CN=J. Smith,OU=Sales,O=Widget Inc.,C=US",
	},
	{
		seq: pkix.RDNSequence{
			pkix.RelativeDistinguishedNameSET{
				pkix.AttributeTypeAndValue{Type: pkix.OidUniqueID, Value: "JSmith"},
			},
			pkix.RelativeDistinguishedNameSET{
				pkix.AttributeTypeAndValue{Type: pkix.OidDomainComponent, Value: "Sales"},
			},
			pkix.RelativeDistinguishedNameSET{
				pkix.AttributeTypeAndValue{Type: pkix.OidDomainComponent, Value: "Widget Inc."},
			},
			pkix.RelativeDistinguishedNameSET{
				pkix.AttributeTypeAndValue{Type: pkix.OidDomainComponent, Value: "US"},
			},
		},
		want: "UID=JSmith,DC=Sales,DC=Widget Inc.,DC=US",
	},
	{
		seq: pkix.RDNSequence{
			pkix.RelativeDistinguishedNameSET{
				pkix.AttributeTypeAndValue{Type: pkix.OidCommonName, Value: "A"},
			},
			pkix.RelativeDistinguishedNameSET{
				pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Value: "golang.org"},
			},
			pkix.RelativeDistinguishedNameSET{
				pkix.AttributeTypeAndValue{Type: pkix.OidCountry, Value: "US"},
			},
		},
		want: "CN=A,1.2.3.4.5=#130a676f6c616e672e6f7267,C=US",
	},
}

func TestRDNSequenceString(t *testing.T) {
	// Test some extra cases that get lost in pkix.Name conversions such as
	// multi-valued attributes.

	for i, test := range testsRDNStrings {
		if got := test.seq.String(); got != test.want {
			t.Errorf("#%d: String() = \n%s\n, want \n%s", i, got, test.want)
		}
	}
}

func TestParse2RDNSequence(t *testing.T) {
	for i, test := range testsRDNStrings {
		rdns := pkix.RDNSequence{}
		err := rdns.Parse(test.want)
		if err != nil {
			t.Errorf("#%d: got error %v", i, err)
		}
		if !reflect.DeepEqual(rdns, test.seq) {
			t.Errorf("#%d: String() = \n%s\n, want \n%s", i, rdns.String(), test.want)
		}
	}
}
