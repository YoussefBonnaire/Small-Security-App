# Takes in list of signatories (signartures + public key) and a document and checks whether document is signed by signatories
import sys
from pgpy import PGPKey, PGPSignature, PGPMessage

signatures_files_list = sys.argv[0]
public_key_files_list = sys.argv[1]
plaintext_file = sys.argv[2]

# get key
publickeys = []
with open(public_key_files_list, "r") as publickey_files:
    for publickey_file in publickey_files:
        key = PGPKey.from_file(publickey_file)
        publickeys.append(key)

# get message
file_message = PGPMessage.new(plaintext_file, file=True)

# verify
for publickey in publickeys:
    verifications = publickey.verify(file_message, signature)
    for signature in verifications.good_signatures:
        if signature.verified:
            print("Verified")
            exit()

    print("Not Verified!")

