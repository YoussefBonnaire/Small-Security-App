import sys
from pgpy import PGPKey, PGPMessage, PGPSignature
from cryptography import x509

signatureListFiles = 'app_files/signatures_list'
certificate_files_list = 'app_files/certificate_list'
plaintext_file = 'Plain_text_J&Y.txt'
#Read in signatures and certificates
signatureList = []
with open(signatureListFiles,"r") as sigFiles:
    files = sigFiles.read().splitlines()
    for file in files:
        signature = PGPSignature.from_file(file)
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

# verify
for i in range(len(signatureList)):
    if isinstance(certificates[i], PGPKey):
        verifications = certificates[i].fingerprint.keyid == signatureList[i].signer
        if(verifications):
            print('PGP verified')
        else:
            print('Not PGP Verified')
    else:
        X509Pub = certificates[i].public_key()
        if X509Pub.verify(signatureList[i]):
            print('X509 verified')
        else:
            print('Not X509 verified')
