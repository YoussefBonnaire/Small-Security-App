# Takes in list of public key sig files and a document and checks whether document is signed by signatories
import sys
import pgpy
from pgpy import PGPKey, PGPSignature
from OpenSSL.crypto import FILETYPE_PEM, verify, X509, load_certificate

signatures_files_list = sys.argv[1]
#signatures_files_list = 'app_files/signatures_list'  # Hardcoded for testing

certificate_files_list = sys.argv[2]
#certificate_files_list = 'app_files/certificate_list'  # Hardcoded for testing

plaintext_file = sys.argv[3]
#plaintext_file = 'Plain_text_J&Y.txt'  # Hardcoded for testing

# get key
certificates = []
with open(certificate_files_list, "r") as certificate_files:
    cert_lines = certificate_files.read().splitlines()
    for certificate_file in cert_lines:
        try:
            key, _ = PGPKey.from_file(certificate_file)
            certificates.append(key)
        except:
            with open(certificate_file, "rb") as certificate:
                cert = certificate.read()
                crtObj = load_certificate(FILETYPE_PEM, cert)
                certificates.append(crtObj)

signatures = []
with open(signatures_files_list, "r") as signatures_files:
    sig_lines = signatures_files.read().splitlines()
    for signatures_file in sig_lines:
        try:
            signature = PGPSignature.from_file(signatures_file)
            signatures.append(signature)
        except:
            with open(signatures_file, 'rb') as f:
                signature = f.read()
                signatures.append(signature)

if len(signatures) != len(certificates):
    raise ValueError('Number of certificates and signatures are not equal')

# Get document
with open(plaintext_file, "r") as plainfile:
    plain_text = plainfile.read()

# verify
for i in range(len(certificates)):
    if isinstance(certificates[i], pgpy.pgp.PGPKey):
        verifications = certificates[i].verify(plain_text, signature=signatures[i])
        if verifications:
            print(f"Signature: {sig_lines[i]} CONFIRMED with cert {cert_lines[i]}!")
        else:
            print(f"Signature: {sig_lines[i]} NOT CONFIRMED with cert {cert_lines[i]}!")
    elif isinstance(certificates[i], X509):
        with open(plaintext_file, "rb") as plainfile:
            plain_text = plainfile.read()
        try:
            verifications = verify(certificates[i], signatures[i], plain_text, "sha256")
            if verifications is None:
                print(f"Signature: {sig_lines[i]} CONFIRMED with cert {cert_lines[i]}!")
        except:
            print(f"Signature: {sig_lines[i]} NOT CONFIRMED with cert {cert_lines[i]}!")
    else:
        raise ValueError(f'Public key for sig {sig_lines[i]} is not of correct type')

print('Finished')
