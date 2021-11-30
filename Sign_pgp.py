import sys
from pgpy import PGPKey, PGPMessage

plaintext = sys.argv[1]
privatekey_file = sys.argv[2]
passphrase = sys.argv[3]

# get the key from the keyring
with open(privatekey_file, "r") as privatekeyfile:
    pkdata = privatekeyfile.read()
privkey = PGPKey()
privkey.parse(pkdata)

# sign the file
with open(plaintext, "r") as plainfile:
    plain_text = plainfile.read()
message = PGPMessage.new(plain_text)
print(message)

#with privkey.unlock(passphrase):
signature = privkey.sign(message)
print(signature)
# write the signature
with open(plaintext[:-3] + '.' + privatekey_file[-16:]  +'.sig', "w+") as sigfile:
    sigfile.write(str(signature))