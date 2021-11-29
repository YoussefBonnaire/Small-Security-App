import sys
from pgpy import PGPKey, PGPMessage, PGPSignature
from cryptography import x509

signatureListFiles = 'app_files/signatures_list'
x509CertListFiles = 'app_files/x509_cert_list'
pgpCertListFiles = 'app_files/pgp_cert_list'
plaintext_file = 'Plain_text_J&Y.txt'
#Read in signatures and certificates
signatureList = []
with open(signatureListFiles,"r") as sigFiles:
    files = sigFiles.read().splitlines()
    for file in files:
        signature = PGPSignature.from_file(file)
        signatureList.append(signature)

x509CertList = []
with open(x509CertListFiles,"r") as x509CertFiles:
    files = x509CertFiles.read().splitlines()
    for file in files:
        certificate = x509.load_pem_x509_certificate(file)
        x509CertList.append(certificate)

pgpCertList = []
with open(pgpCertListFiles,"r") as pgpCertFile:
    files = pgpCertFile.read().splitlines()
    for file in files:
        certificate = PGPKey.from_file(file)
        pgpCertList.append(certificate)

with open(plaintext_file, "r") as plainfile:
    plain_text = plainfile.read()

# verify
for i in range(len(signatureList)):
    verifications = pgpCertList[i].verify(plain_text, signatureList[i])
    sigVerified = False
    for verSig in verifications.good_signatures:
        if verSig.verified:
            sigVerified = True
    if(sigVerified):
        print('PGP verified')
    else:
        print('Not PGP Verified')
