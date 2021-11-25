# Takes in list of public key sig files and a document and checks whether document is signed by signatories
import sys
from pgpy import PGPKey, PGPSignature

#signatures_files_list = sys.argv[1]
signatures_files_list = 'app_files/signatures_list' # Hardcoded for testing

#public_key_files_list = sys.argv[2]
public_key_files_list = 'app_files/publickey_list'# Hardcoded for testing

#plaintext_file = sys.argv[3]
plaintext_file = 'Plain_text_J&Y.txt' # Hardcoded for testing

# get key
publickeys = []
with open(public_key_files_list, "r") as publickey_files:
    lines = publickey_files.read().splitlines()
    for publickey_file in lines:
        key, _ = PGPKey.from_file(publickey_file)
        publickeys.append(key)

signatures = []
with open(signatures_files_list, "r") as signatures_files:
    lines = signatures_files.read().splitlines()
    for signatures_file in lines:
        signature = PGPSignature.from_file(signatures_file)
        signatures.append(signature)

# Get document
with open(plaintext_file, "r") as plainfile:
    plain_text = plainfile.read()

# verify
for i in range(len(publickeys)):
    verifications = publickeys[i].verify(plain_text, signature=signatures[i])
    if verifications:
        print(f"Public key id: {publickeys[i].fingerprint.keyid} Verified")
    else: print(f"Public key id: {publickeys[i].fingerprint.keyid} Not Verified!")
print('Finished')
