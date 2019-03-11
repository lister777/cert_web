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
        try:
            certs = cert_checker(hostname)
        except Exception as e:
            return render_template('cert_validator/ssl_checker.html', error=e)
    return render_template('cert_validator/ssl_checker.html', certs=certs)
    
def cert_checker(hostname):
    ctx = SSL.Context(SSL.TLSv1_2_METHOD)
    conn = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    
    try:
        hostname = hostname_validator(hostname)
        try:
            conn.connect_ex((hostname,443))
            conn.do_handshake()
        except:
            raise Exception('Couldn\'t establish the https connection to %s'%(hostname))
        certs_x509 = conn.get_peer_cert_chain()
        conn.get_peer_finished()
        certs_pem = map(lambda c: (crypto.dump_certificate(crypto.FILETYPE_PEM, c.to_cryptography()).decode('utf-8')), certs_x509)
        certs = zip(certs_x509, certs_pem)
        return list(certs)[::-1]
    except Exception as e:
        raise e
    
def hostname_validator(hostname):
    import re
    regex = re.compile(
        r'^(https?://)?'  # http:// or https://
        r'((?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    try:
        match = regex.match(hostname).groups()
        return ''.join(match[1])
    except Exception as e:
        raise Exception('%s is an Invaild hostname'%(hostname))