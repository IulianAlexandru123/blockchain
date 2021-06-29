
# coding: utf-8

# In[39]:

import base64

from hashlib import sha256
from inspect import signature
from os import EX_CANTCREAT
import cryptography
from cryptography import utils
from cryptography.exceptions import InvalidSignature
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from flask import Flask
from flask_cors import CORS, cross_origin
import json
import time
import binascii

from flask import Flask, request
import requests


class Block:

    def __init__(self, index, transactions, timestamp, previous_hash, nonce, hash, timestamphash, signature, public_key):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = hash
        self.timestamphash = timestamphash
        self.signature = signature
        self.public_key = public_key

    def compute_hash(self):
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return sha256(block_string.encode()).hexdigest()

    def compute_timestamphash(self):
        return sha256((str(self.timestamp) + self.hash).encode()).hexdigest()

    def verify_hash(self):
        dict = {"hash": 0, "index": self.index, "nonce": self.nonce, "previous_hash": self.previous_hash, "public_key": 0,
                "signature": 0, "timestamp": self.timestamp, "timestamphash": 0, "transactions": self.transactions}
        block_string = json.dumps(dict, sort_keys=True)
        return sha256(block_string.encode()).hexdigest() == self.hash

    def compute_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key = private_key.public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.public_key = binascii.hexlify(
            pem).decode('ascii')
        try:
            encrypted = private_key.sign(
                str.encode(self.timestamphash),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except UnsupportedAlgorithm:
            print("Signing failed")
        return encrypted

    def verify_signature(self):
        public_key = serialization.load_pem_public_key(
            binascii.unhexlify(self.public_key),
            backend=default_backend()
        )
        try:
            public_key.verify(
                base64.b64decode(self.signature),
                str.encode(self.timestamphash),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            is_signature_correct = True
        except InvalidSignature:
            is_signature_correct = False
        return is_signature_correct

    def sign_block(self):
        uri = 'http://timestamp_service:5000/get_public_key'
        response = requests.get(uri)
        self.public_key = response.json()['public_key']
        uri = 'http://timestamp_service:5000/sign_transaction'
        params = {'hash': self.timestamphash}
        response = requests.get(url=uri, params=params)
        return response.json()['signature']

    def verify_from_service(self):
        uri = 'http://verification_service:4000/verify_transaction'
        params = {'hash': self.hash, 'timestamp': self.timestamp, 'timestamphash': self.timestamphash,
                  'signature': self.signature, 'public_key': self.public_key}
        response = requests.get(url=uri, params=params)
        return response.json()['signature']


class Blockchain:
    difficulty = 2

    def __init__(self):
        self.unconfirmed_transactions = []
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0, [], time.time(), "0", 0, 0, 0, 0, 0)
        genesis_block.hash = genesis_block.compute_hash()
        genesis_block.timestamphash = genesis_block.compute_timestamphash()
        genesis_block.signature = genesis_block.sign_block()

        self.chain.append(genesis_block)

    @ property
    def last_block(self):
        return self.chain[-1]

    def add_block(self, block, proof):
        previous_hash = self.last_block.hash

        if previous_hash != block.previous_hash:
            return False

        if not self.is_valid_proof(block, proof):
            return False

        block.hash = proof
        block.timestamphash = block.compute_timestamphash()
        block.signature = block.sign_block()

        self.chain.append(block)

        chain_data = []
        for block in blockchain.chain:
            chain_data.append(block.__dict__)
        with open('data.json', 'w') as f:
            json.dump({"length": len(chain_data),
                       "chain": chain_data}, f)
        return True

    def is_valid_proof(self, block, block_hash):
        return (block_hash.startswith('0' * Blockchain.difficulty) and
                block_hash == block.compute_hash())

    def proof_of_work(self, block):
        block.nonce = 0

        computed_hash = block.compute_hash()
        while not computed_hash.startswith('0' * Blockchain.difficulty):
            block.nonce += 1
            computed_hash = block.compute_hash()

        return computed_hash

    def add_new_transaction(self, transaction):
        if(len(self.unconfirmed_transactions) == 0):
            self.unconfirmed_transactions.append(transaction)

    def mine(self):
        if not self.unconfirmed_transactions:
            return False

        last_block = self.last_block

        new_block = Block(index=last_block.index + 1,
                          transactions=self.unconfirmed_transactions,
                          timestamp=time.time(),
                          previous_hash=last_block.hash, nonce=0, hash=0, timestamphash=0, signature=0, public_key=0)

        proof = self.proof_of_work(new_block)
        self.add_block(new_block, proof)
        self.unconfirmed_transactions = []

        return new_block.index

    def load_blockchain(self):
        try:
            with open('data.json') as json_file:
                data = json.load(json_file)
                self.chain = []
                for p in data['chain']:
                    new_block = Block(p['index'], p['transactions'], p['timestamp'], p['previous_hash'],
                                      p['nonce'], p['hash'], p['timestamphash'], p['signature'], p['public_key'])
                    self.chain.append(new_block)
        except FileNotFoundError:
            self.create_genesis_block()


app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'
blockchain = Blockchain()

# In[41]:


@ app.route('/chain', methods=['GET'])
def get_chain():
    chain_data = []
    blockchain.chain = []
    blockchain.load_blockchain()
    for block in blockchain.chain:
        chain_data.append(block.__dict__)
    return json.dumps({"length": len(chain_data),
                       "chain": chain_data})


@ app.route('/create_blockchain')
def create_blockchain():
    chain_data = []
    blockchain.chain = []
    blockchain.unconfirmed_transactions = []
    blockchain.create_genesis_block()
    for block in blockchain.chain:
        chain_data.append(block.__dict__)
    with open('data.json', 'w') as f:
        json.dump({"length": len(chain_data),
                   "chain": chain_data}, f)
    return json.dumps({"Blockchain created": blockchain.load_blockchain()})


@ app.route('/mine')
def mine_block():
    blockchain.load_blockchain()
    return json.dumps({"Block created. ID: ": blockchain.mine()})


@ app.route('/transaction')
def add_transaction():
    return json.dumps({"Transaction added ": blockchain.add_new_transaction("Transaction" + str(len(blockchain.chain)))})


@ app.route('/restore')
def restore_blockchain():
    return json.dumps({"Transaction added ": blockchain.load_blockchain()})


@ app.route('/verify_signature')
def verify():
    result = []
    blockchain.load_blockchain()
    for block in blockchain.chain:
        if(not block.verify_hash()):
            result.append(False)
        else:
            result.append(block.verify_from_service())
    return json.dumps({"signature": result})


# In[45]:
#app.run(debug=True, port=50162)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int("3000"), debug=True)
