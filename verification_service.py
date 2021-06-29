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


class VerificationService:
    def verify_transaction(self, hash, timestamp, timestamphash, signature, public_key):
        pub_key = serialization.load_pem_public_key(
            binascii.unhexlify(public_key),
            backend=default_backend()
        )
        if(sha256((str(timestamp) + hash).encode()).hexdigest() != timestamphash):
            return False
        try:
            pub_key.verify(
                base64.b64decode(signature),
                str.encode(timestamphash),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            is_signature_correct = True
        except InvalidSignature:
            is_signature_correct = False
        print(is_signature_correct)
        return is_signature_correct


app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'
vericationService = VerificationService()


@app.route('/verify_transaction', methods=['GET'])
def verify_transaction():
    result = vericationService.verify_transaction(request.args.get('hash'), request.args.get(
        'timestamp'), request.args.get('timestamphash'), request.args.get('signature'), request.args.get('public_key'))
    return json.dumps({"signature": result})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int("4000"), debug=True)
