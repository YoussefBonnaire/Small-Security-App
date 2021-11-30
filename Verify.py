import sys

from OpenSSL import crypto
from OpenSSL.crypto import verify
from pgpy import PGPKey, PGPSignature
from cryptography import x509

#signatures_files_list = sys.argv[1]
signatureListFiles = 'app_files/signatures_list'  # Hardcoded for testing
#certificate_files_list = sys.argv[2]
certificate_files_list = 'app_files/certificate_list'  # Hardcoded for testing
#plaintext_file = sys.argv[3]
plaintext_file = 'Plain_text_J&Y.txt'  # Hardcoded for testing

#Read in signatures and certificates
signatureList = []
with open(signatureListFiles,"r") as sigFiles:
    files = sigFiles.read().splitlines()
    for file in files:
        try:
            signature = PGPSignature.from_file(file)
            signatureList.append(signature)
        except:
            with open(file, 'rb') as f:
                signature = f.read()
                signatureList.append(signature)


certificates =[]
with open(certificate_files_list, "r") as certificate_files:
    cert_lines = certificate_files.read().splitlines()
    for certificate_file in cert_lines:
        try:
            certificate, _ = PGPKey.from_file(certificate_file)
            certificates.append(certificate)
        except:
            with open(certificate_file, "rb") as certificate:
                cert = certificate.read()
                crtObj = x509.load_pem_x509_certificate(cert)
                certificates.append(crtObj)

with open(plaintext_file, "rb") as plainfile:
    plain_text = plainfile.read()

# verify
for i in range(len(signatureList)):
    if isinstance(certificates[i], PGPKey):
        verifications = certificates[i].fingerprint.keyid == signatureList[i].signer
        if(verifications):
            print('PGP verified')
        else:
            print('Not PGP Verified')
    else:
        #if certificates[i].fingerprint(certificates[i].signature_hash_algorithm) == signatureList[i].signer_fingerprint:
        try:
            if verify(certificates[i], signatureList[i], plain_text, "sha256") is None:
                print('X509 verified')
        except crypto.Error:print('Not X509 verified, wrong signature')
