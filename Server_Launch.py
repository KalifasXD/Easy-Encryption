from flask import Flask
import ssl
from routes import app_routes
from config import MAX_CONTENT_LENGTH, UPLOAD_FOLDER

# Initialize Flask app
app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
app.register_blueprint(app_routes)

# SSL context setup for secure communication
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('cert.pem', 'key.pem')  # Load the cert and key files

if __name__ == '__main__':
    app.run(ssl_context=context, host='0.0.0.0', port=443)
