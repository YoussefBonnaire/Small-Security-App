import sys
from OpenSSL import crypto
from OpenSSL.crypto import verify
from pgpy import PGPKey, PGPSignature
from cryptography import x509


try:
    signatureListFiles = sys.argv[1]
    certificate_files_list = sys.argv[2]
    plaintext_file = sys.argv[3]
except:
    signatureListFiles = 'app_files/signatures_list'  # Hardcoded for testing
    certificate_files_list = 'app_files/certificate_list'  # Hardcoded for testing
    plaintext_file = 'Plain_text_J&Y.txt'  # Hardcoded for testing


# Read in signatures and certificates
signatureList = []
with open(signatureListFiles,"r") as sigFiles:
    files = sigFiles.read().splitlines()
    for file in files:
        # Load pgp signatures
        try:
            signature = PGPSignature.from_file(file)
            signatureList.append(signature)
        # Load x509 signatures
        except:
            with open(file, 'rb') as f:
                signature = f.read()
                signatureList.append(signature)


certificates =[]
with open(certificate_files_list, "r") as certificate_files:
    cert_lines = certificate_files.read().splitlines()
    for certificate_file in cert_lines:
        try:
            # Load pgp certificates (public keys)
            certificate, _ = PGPKey.from_file(certificate_file)
            certificates.append(certificate)
        except:
            # Load x509 certificates
            with open(certificate_file, "rb") as certificate:
                cert = certificate.read()
                crtObj = x509.load_pem_x509_certificate(cert)
                certificates.append(crtObj)

with open(plaintext_file, "rb") as plainfile:
    plain_text = plainfile.read()

# verify
for i in range(len(signatureList)):
    if isinstance(certificates[i], PGPKey):
        # verify pgp sig and certificate match
        verifications = certificates[i].fingerprint.keyid == signatureList[i].signer
        if(verifications):
            print('PGP verified')
        else:
            print('Not PGP Verified')
    else:
        # verify x509 sig and certificate match
        # if certificates[i].fingerprint(certificates[i].signature_hash_algorithm) == signatureList[i].signer_fingerprint:
        try:
            if verify(certificates[i], signatureList[i], plain_text, "sha256") is None:
                print('X509 verified')
        except crypto.Error:print('Not X509 verified, wrong signature')
