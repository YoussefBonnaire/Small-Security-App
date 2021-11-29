from OpenSSL import crypto
import os
import sys
import datetime

#Variables
TYPE_RSA = crypto.TYPE_RSA
TYPE_DSA = crypto.TYPE_DSA
now = datetime.datetime.now()
d = now.date()

#Pull these out of scope
cn = input("Enter the Domain: ")
key = crypto.PKey()
keypath = cn + '.key'
csrpath = cn + '.csr'
crtpath = cn + '.crt'

#Generate the key


def generatekey():

    if os.path.exists(keypath):
        print("Certificate file exists, aborting.")
        print(keypath)
        sys.exit(1)
    #Else write the key to the keyfile
    else:
        print("Generating Key Please standby")
        key.generate_key(TYPE_RSA, 4096)
        f = open(keypath, "wb")
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        f.close()

    return key

generatekey()

#Generate CSR

def generatecsr():
    c = 'UK'
    st = 'Midlothian'
    l = 'Edinburgh'
    o = 'JAYO'
    ou = 'testers'


    req = crypto.X509Req()
    req.get_subject().CN = cn
    req.get_subject().C = c
    req.get_subject().ST = st
    req.get_subject().L = l
    req.get_subject().O = o
    req.get_subject().OU = ou
    req.set_pubkey(key)
    req.sign(key, b"sha256")

    if os.path.exists(csrpath):
        print ("Certificate File Exists, aborting.")
        print(csrpath)
    else:
        f = open(csrpath, "wb")
        f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))
        f.close()
        print("Success")

#Generate the certificate
    reply = str(input('Is this a Self-Signed Cert (y/n): ')).lower().strip()

    if reply[0] == 'y':
        cert = crypto.X509()
        cert.get_subject().CN = cn
        cert.get_subject().C = c
        cert.get_subject().ST = st
        cert.get_subject().L = l
        cert.get_subject().O = o
        cert.get_subject().OU = ou
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(315360000)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)

        cert.add_extensions([
            crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
        ])

        cert.add_extensions([
            crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always,issuer", issuer=cert),
        ])

        cert.add_extensions([
            crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"),
            crypto.X509Extension(b"keyUsage", True, b"digitalSignature, keyCertSign, cRLSign"),
        ])

        cert.sign(key, b"sha256")
        if os.path.exists(crtpath):
            print ("Certificate File Exists, aborting.")
            print (crtpath)
        else:
            f = open(crtpath, "wb")
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
            f.close()
            print ("CRT Stored Here :" + crtpath)

generatecsr()

print ("Key Stored Here :" + keypath)
print ("CSR Stored Here :" + csrpath)