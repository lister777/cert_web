import functools
import socket

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash
from OpenSSL import SSL, crypto


cg = Blueprint('csr_generator', __name__, url_prefix='/csr-generator')

@cg.route('/', methods=('GET', 'POST'))
def csr_generator():
    outputs = None
    if request.method == 'POST' and request.form['ealg'] == 'RSA':
        bits = int(request.form['rsaeb'])
        digest =  request.form['halg']
        TYPE_RSA = crypto.TYPE_RSA
        
        pkey = createKeyPair(TYPE_RSA, bits)
        
        csr = createCertRequest(pkey, digest=digest, 
        O=request.form['O'],
        OU=request.form['OU'],
        L=request.form['L'],
        ST=request.form['ST'],
        C=request.form['C'],
        emailAddress=request.form['emailAddress'],
        CN=request.form['CN']
        )
        
        csr_pem = crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr).decode('utf-8')
        pkey_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey).decode('utf-8')
        csrfilename = request.form['CN'] +".csr"
        keyfilename = request.form['CN'] +".key"
        outputs = [(0,csr_pem,csrfilename), (1,pkey_pem,keyfilename)]
        
    return render_template('cert_validator/csr_generator.html', outputs=outputs)
    
def createKeyPair(type, bits):
    """
    Create a public/private key pair.
    Arguments: type - Key type, must be one of TYPE_RSA and TYPE_DSA
               bits - Number of bits to use in the key
    Returns:   The public/private key pair in a PKey object
    """
    pkey = crypto.PKey()
    pkey.generate_key(type, bits)
    return pkey
    
def createCertRequest(pkey, digest="sha256", **name):
    """
    Create a certificate request.
    Arguments: pkey   - The key to associate with the request
               digest - Digestion method to use for signing, default is sha256
               **name - The name of the subject of the request, possible
                        arguments are:
                          C     - Country name
                          ST    - State or province name
                          L     - Locality name
                          O     - Organization name
                          OU    - Organizational unit name
                          CN    - Common name
                          emailAddress - E-mail address
    Returns:   The certificate request in an X509Req object
    """
    req = crypto.X509Req()
    subj = req.get_subject()

    for key, value in name.items():
        setattr(subj, key, value)

    req.set_pubkey(pkey)
    req.sign(pkey, digest)
    return req