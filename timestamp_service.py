import cryptography
from cryptography import utils
from cryptography.exceptions import InvalidSignature
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64
import binascii
import json
import time

from hashlib import sha256
from flask import Flask
from flask_cors import CORS, cross_origin
from flask import request


class TimeStampService:
    def sign_transaction(self, hash):
        with open("private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        try:
            signature = private_key.sign(
                str.encode(hash),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except UnsupportedAlgorithm:
            print("Signing failed")
        signature = base64.b64encode(signature).decode('ascii')
        return json.dumps({"timestamp": time.time(), "signature": signature})

    def get_public_key(self):
        with open("public_key.pem", "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return binascii.hexlify(pem).decode('ascii')


app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'
timeStampService = TimeStampService()


@app.route('/sign_transaction', methods=['GET'])
def sign_transaction():
    return timeStampService.sign_transaction(request.args.get('hash'))


@ app.route('/get_public_key', methods=['GET'])
def public_key():
    return json.dumps({"public_key": timeStampService.get_public_key()})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int("5000"), debug=True)
