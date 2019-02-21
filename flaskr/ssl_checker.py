import functools
import socket

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash
from OpenSSL import SSL, crypto



sc = Blueprint('ssl_checker', __name__, url_prefix='/ssl-checker')

@sc.route('/', methods=('GET', 'POST'))
def sslchecker():
    certs = []
    if request.method == 'POST' and request.form['url']:
        hostname = request.form['url']
        certs = cert_checker(hostname)
        
    return render_template('cert_validator/ssl_checker.html', certs=certs)
    
def cert_checker(hostname):
    ctx = SSL.Context(SSL.SSLv23_METHOD)
    
    conn = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    conn.connect_ex((hostname,443))
    conn.do_handshake()
    
    cert_chain = conn.get_peer_cert_chain()
    
    conn.get_peer_finished()
    

    certs_pem = map(lambda c: (crypto.dump_certificate(crypto.FILETYPE_PEM, c.to_cryptography()).decode('utf-8')), cert_chain)
    certs = zip(cert_chain, certs_pem)
    return certs