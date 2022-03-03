import sys
# import os
# import ssl
import OpenSSL

def main(*argv):

    # load certificate
    cert = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM, 
        open('test2.pem').read()
    )

    # get key from the certificate
    key = cert.get_pubkey()

    # dump both public key and private key
    OpenSSL.crypto.dump_certificate( OpenSSL.crypto.FILETYPE_PEM, cert )
    OpenSSL.crypto.dump_privatekey( OpenSSL.crypto.FILETYPE_PEM, key )

    # generate p12
    p12 = OpenSSL.crypto.PKCS12()
    p12.set_privatekey( key )
    p12.set_certificate( cert )
    
    open( "result.p12", 'wb' ).write( p12.export() )

if __name__ == "__main__":
    rc = main(sys.argv[1:])
    sys.exit(rc)