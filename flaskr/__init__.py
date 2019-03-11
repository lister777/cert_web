import os
import datetime
from flask import Flask




def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev',
        #DATABASE=os.path.join(app.instance_path, 'flaskr.sqlite')
    )

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # a simple page that says hello
    @app.route('/hello')
    def hello():
        return 'Hello, World!'

    from . import ssl_checker
    app.register_blueprint(ssl_checker.sc)
    
    from . import csr_generator
    app.register_blueprint(csr_generator.cg)
    
    from . import index
    app.register_blueprint(index.bp)
    app.add_url_rule('/', endpoint='index')

    def time_convert(ASN_time):
        return datetime.datetime.strptime(ASN_time.decode('ascii'), '%Y%m%d%H%M%SZ')

    app.jinja_env.globals.update(time_convert=time_convert)

    
    return app