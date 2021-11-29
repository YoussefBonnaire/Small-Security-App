import sys

from pgpy import PGPKey, PGPMessage, PGPSignature, errors
from cryptography import x509

signatureListFiles = 'app_files/signatures_list'
certificate_files_list = 'app_files/certificate_list'
plaintext_file = 'Plain_text_J&Y.txt'
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
        if certificates[i].fingerprint(certificates[i].signature_hash_algorithm) == signatureList[i].signer_fingerprint:
            print('X509 verified')
        else:
            print('Not X509 verified')
