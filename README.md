# gocert

This module is merging several module in one:
- asn1 is a fork of encoding/asn1 from go with enhancement for strings (see asn1/README.md)
- x509 is a fork of crypto/x059 from go with enhancement for strings and subject alternate name (see x509/README.md)
	- certificate and CRL management
	- pkcs8 
- pkcs5 is refactored fork of github.com/elastic/pkcs8 by isolating the en/decryption of pkcs8 key
	- used 

This module is compatible with go 1.25+. Not tested with earlier version.

