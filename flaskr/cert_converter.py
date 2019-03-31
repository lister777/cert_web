import functools
import socket

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash
from OpenSSL import SSL, crypto


cc = Blueprint('cert_converter', __name__, url_prefix='/cert-converter')

@cc.route('/', methods=('GET', 'POST'))
def cert_converter():
    output_cert = None
    source_format_checkbox_list = request.form.getlist('sourceformat')
    target_format_checkbox_list = request.form.getlist('targetformat')
    if request.method == 'POST' and 'PEM' in source_format_checkbox_list and 'DER' in target_format_checkbox_list:
        if request.form['sourcefile_pastebox']:
            pem_cert = request.form['sourcefile_pastebox']
            x509_cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_cert.encode('utf-8'))
            der_cert = crypto.dump_certificate(crypto.FILETYPE_ASN1, x509_cert)
            print(der_cert)
            file_name = x509_cert.get_subject().commonName + '.der'
            output_cert = [der_cert, file_name]
    
    if request.method == 'POST' and 'DER' in source_format_checkbox_list and 'PEM' in target_format_checkbox_list:
        if request.files['sourcefile']:
            der_cert = request.files['sourcefile'].read()
            #der_cert = request.form['sourcefile_pastebox'].encode('utf-8')
            x509_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der_cert)
            pem_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, x509_cert).decode('utf-8')
            file_name = x509_cert.get_subject().commonName + '.pem'
            output_cert = [pem_cert, file_name]
            
    return render_template('cert_validator/cert_converter.html', cert=output_cert)