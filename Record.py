# Takes in list of public key sig files and a document and checks whether document is signed by signatories
from pgpy import PGPKey, PGPSignature
from OpenSSL.crypto import load_publickey, FILETYPE_PEM, verify, X509, load_certificate,dump_publickey

# signatures_files_list = sys.argv[1]
signatures_files_list = 'app_files/signatures_list'  # Hardcoded for testing

# public_key_files_list = sys.argv[2]
public_key_files_list = 'app_files/publickey_list'  # Hardcoded for testing

# plaintext_file = sys.argv[3]
plaintext_file = 'Plain_text_J&Y.txt'  # Hardcoded for testing

# get key
publickeys = []
with open(public_key_files_list, "r") as publickey_files:
    lines = publickey_files.read().splitlines()
    for publickey_file in lines:
        try:
            key, _ = PGPKey.from_file(publickey_file)
            publickeys.append(key)
        except:
            with open(publickey_file, "rb") as certificate:
                cert = certificate.read()
                crtObj = load_certificate(FILETYPE_PEM, cert)
                publickeys.append(crtObj)


signatures = []
with open(signatures_files_list, "r") as signatures_files:
    lines = signatures_files.read().splitlines()
    for signatures_file in lines:
        try:
            signature = PGPSignature.from_file(signatures_file)
            signatures.append(signature)
        except:
            with open(signatures_file, 'rb') as f:
                signature = f.read()
                signatures.append(signature)

# Get document
with open(plaintext_file, "r") as plainfile:
    plain_text = plainfile.read()

# verify
for i in range(len(publickeys)):
    try:
        verifications = publickeys[i].verify(plain_text, signature=signatures[i])
        with open(public_key_files_list, "r") as publickey_files:
            lines = publickey_files.read().splitlines()
            if verifications:
                print(f"Public key id: {lines[i]} Verified")
            else:
                print(f"Public key id: {lines[i]} not Verified!")
    except:
        with open(plaintext_file, "rb") as plainfile:
            plain_text = plainfile.read()
        try:
            verifications = verify(publickeys[i], signatures[i], plain_text, "sha256")
            if verifications is None:
                print(f"Public key id: {lines[i]} Verified")
        except:
            print(f"Public key id: {lines[i]} not Verified")

print('Finished')
