import sys
from OpenSSL.crypto import sign, load_privatekey, FILETYPE_PEM, load_pkcs12

plaintext = sys.argv[1]
privatekey_file = sys.argv[2]
priv_passphrase = sys.argv[3]
passw = bytes(priv_passphrase, 'utf-8')

# get the key from the keyring
with open(privatekey_file, "r") as privatekeyfile:
    pkdata = privatekeyfile.read()
    pkey = load_privatekey(FILETYPE_PEM, pkdata, passw)


# sign the file
with open(plaintext, "rb") as plainfile:
    plain_text = plainfile.read()

#with privkey.unlock(priv_passphrase):
signature = sign(pkey, plain_text, "sha256")

# write the signature
with open( plaintext[:-3] + privatekey_file[-7:] +'.sig', "wb+") as sigfile:
    sigfile.write(signature)