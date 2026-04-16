# crypto/x509

Fork of the official "crypto/x509".

This module with the following changes:
- adds subjectAltNames extensions (RegisterID, DirectoryNames and OtherName)
- adds dynamic strings encoding for UTF8, IA5, NUMERIC, Teletex/T61 and BMP (linked to embeded asn1)
- manage only ordered fields in subject, issuer and altSubjectName/directoryNames (more inline with Directory Information Tree)