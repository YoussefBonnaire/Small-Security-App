import sys
from pgpy import PGPKey, PGPMessage

plaintext = sys.argv[1]
privatekey_file = sys.argv[2]
priv_passphrase = sys.argv[3]

# get the key from the keyring

with open(privatekey_file, "r") as privatekeyfile:
    pkdata = privatekeyfile.read()
privkey = PGPKey()
privkey.parse(pkdata)

# sign the file
message = PGPMessage.new(plaintext, file=True)
#with privkey.unlock(priv_passphrase):
signature = privkey.sign(message)

# write the signature
with open(plaintext+'.sig', "w") as sigfile:
    sigfile.write(str(signature))