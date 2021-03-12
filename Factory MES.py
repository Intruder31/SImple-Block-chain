#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Feb  9 15:31:59 2020

@author: vedantdandawate
"""

import json
import hashlib
import time
import requests
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from urllib.parse import urlparse
from flask import Flask, jsonify, request 

self_url = "http://127.0.0.1:5000"

node_id = "Factory MES"

class Blockchain(object):
    
    #Constructor
    def __init__(self):    
        self.__private_key = RSA.generate(1024)
        self.public_key = self.__private_key.publickey()
        self.chain = []
        self.data = []
        self.nodes=set()
        self.register_node(self_url)
        self.new_block("Self",previous_hash = 1, proof = 100) #Genesis block
        
    #Create new block    
    def new_block(self, miner, proof, previous_hash):
        block = {
                'index': len(self.chain) + 1,
                'timestamp': time.asctime( time.localtime(time.time())),
                'miner': miner,
                'data': self.data,
                'proof': proof,
             'previous_hash': previous_hash or self.hash(self.last_block()),
                }
        self.chain.append(block)
        self.data = []
        
        return block
    
    #New Data addition - takes params from POST method
    def add_data(self, receiver, msg):
        self.data.append({
                "sender" : node_id,
                "receiver" : receiver,
                "msg" : base64.encodestring(msg).decode('ascii')
                })
        return self.get_last_block['index'] + 1
    
    #Carry out Proof of Work 
    def generate_pow(self, previous_block):
        
        previous_proof = previous_block['proof']
        previous_hash = self.hash(previous_block)
        
        proof = 0
        
        while self.validate_block(previous_proof,proof, previous_hash) is False: #check if hash end with '3333'
            proof+=1
            
        return proof
        
    #Register new node on network    
    def register_node(self, address):
        new_url = urlparse(address)
        self.nodes.add(new_url.netloc)
        
    #Validate chain--Return boolean after validating
    def validate_chain(self, chain):
        previous_block = chain[0]
        index = 1
                                                            
        while (index < len(chain)):
            block = chain[index]
            previous_block_hash = self.hash(previous_block)
            
            print("\n-----------\n")
            print(f'{previous_block}')
            print(previous_block_hash)
            print(f'{block}')
            print("\n-----------\n")
            
            #Validate chain by checking last hash
            if (previous_block_hash != block['previous_hash']):
                print("Exiting in 1st if")
                return False

            #Validate proofs
            if not self.validate_block(previous_block['proof'],block['proof'], previous_block_hash):
                print("Exiting in 2nd if")
                return False

            previous_block = block
            index += 1

        return True

    def resolve_longest_chain(self):
        new_chain = None
        max_len = len(self.chain)
        
        
        for node in self.nodes:
            response = requests.get(f'http://{node}/chain')
            
            if (response.status_code == 200):
                length = response.json()['length']
                chain = response.json()['chain']
                
                        
                if (length > max_len and self.validate_chain(chain)):
                    new_chain = chain
                    max_len = length
                    

        if (new_chain != None):  
            self.chain = new_chain #Replacing chain
            return True

        return False
    

    def decrypt_message(self, cipher_text):
        
        ct = cipher_text.encode('ascii')
        ct = base64.decodebytes(ct)
        decrypt = PKCS1_OAEP.new(key=self.__private_key)
        decrypted_message = decrypt.decrypt(ct)
        return decrypted_message
       

    #Generate Hash of block using SHA256 hashing
    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()
    
    #Check for valid proof having 5 lead zeros
    @staticmethod
    def validate_block(previous_proof, proof, previous_block_hash):
        to_check = f'{previous_proof}{proof}{previous_block_hash}'.encode()
        to_check_hash = hashlib.sha256(to_check).hexdigest()
        return to_check_hash[:4] == "3333"
    
    @property
    def get_last_block(self):
        return self.chain[-1]
    
flask_path = Flask(__name__)


# Create object
blockchain = Blockchain()

@flask_path.route('/mine', methods=['GET'])
def mine():
    last_block=blockchain.get_last_block
    
    new_proof=blockchain.generate_pow(last_block)
    previous_hash=blockchain.hash(last_block)
    
    block = blockchain.new_block(node_id, new_proof,previous_hash)
    flag = True
    
    for node in blockchain.nodes:
        if(node != urlparse(self_url).netloc):
            response = requests.get(f'http://{node}/nodes/resolve')
            flag = bool(response.json()['replaced']) and flag
    
    response = {
        'message': "New Block added",
        'index': block['index'],
        'Synced_on_network': flag,
        'data': block['data'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200
    
  
@flask_path.route('/send', methods=['POST'])
def new_data_transfer():
    values = request.get_json(force=True)
    required = ["receiver", "msg"]

    #Check if values match required
    if not all(i in values for i in required):
        return 'Data missing', 400 #Throws status 400 - bad request

    receiver = values["receiver"]
    found = False
    for node in blockchain.nodes:
        resp = requests.get(f'http://' + str(node) + '/nodes/id')    
        node_id = str(resp.json()['node_id'])
        if node_id == receiver:
            pk_resp = requests.get(f'http://' + str(node) + '/nodes/publickey')    
            public_key = RSA.importKey(pk_resp.json()["public_key"])
            found = True
            break
    
    if not found:
        return 'Receiver not found', 400
    
    cipher = PKCS1_OAEP.new(key=public_key)

    cipher_text = cipher.encrypt(values["msg"].encode())
    
    index = blockchain.add_data(receiver, cipher_text)
    print(receiver)
    print(cipher_text)
    response = {'message': f'Data will be added to Block {index}'}
    return jsonify(response), 200

@flask_path.route('/chain', methods=['GET'])
def get_full_chain():
    response = {
            'chain': blockchain.chain,
            'length': len(blockchain.chain),
    }
    return jsonify(response), 200

@flask_path.route('/decryptchain', methods=['GET'])
def get_decrypt_chain():
    decrypted_chain = []
    count = 0
    for block in blockchain.chain:
        if len(block['data']) != 0:
            if block['data'][0]['receiver'] == node_id:
                decrypted_message = blockchain.decrypt_message(block['data'][0]['msg'])
                decrypted_message  = decrypted_message .decode()
                block['data'][0]['msg'] = decrypted_message
                count = count + 1
            
        decrypted_chain.append(block)
    
    response = {
            'Decrypted chain' : decrypted_chain,
            'Decrypted messages' : count,
            'length': len(blockchain.chain),
    }
    return jsonify(response), 200

@flask_path.route('/nodes/publickey', methods=['GET'])
def get_public_key():
    response = {
            'public_key': blockchain.public_key.exportKey().decode("utf-8")
    }
    return jsonify(response), 200

@flask_path.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json(force=True)
    nodes = values['nodes']
    synced = True
    if nodes is None:
        return "No nodes found. Please provide valid nodes", 400

    for node in nodes:
        blockchain.register_node(node)
        
    for node in blockchain.nodes:
        if(node != urlparse(self_url).netloc):
            vals = {
                    "nodes": nodes
                    }
            resp = requests.post((f'http://{node}/nodes/setnodes'), data = json.dumps(vals))
            if(resp.status_code == 200):
                synced = bool(resp.json()['status']) and synced
        
    response = {
                'message':'New node(s) added',
                'Sync status': synced,
                'Total_nodes': len(blockchain.nodes)
    }
    return jsonify(response), 200

@flask_path.route('/nodes', methods=['GET'])#_______
def get_nodes():
    node_ids = []
    for node in blockchain.nodes:
        resp = requests.get(f'http://' + str(node) + '/nodes/id')
        node_ids.append(str(resp.json()['node_id']))  
        
    response = {
            'Online_nodes': node_ids,
            'Count':len(blockchain.nodes),
            'Nodes':list(blockchain.nodes)
    }
    print(response)
    return jsonify(response), 200    
  
    
@flask_path.route('/nodes/setnodes', methods = ['POST']) #called  by register_nodes
def set_nodes():
    values = request.get_json(force=True)
    nodes = values['nodes']
    if nodes is None:
        response = {
                'status':False
                }
        return jsonify(response), 400
    else:
        for node in nodes:
            blockchain.register_node(node)
        response = {
                'status':True
                }
        return jsonify(response), 200    
        
    
@flask_path.route('/nodes/id', methods=['GET'])
def get_node_id():
    response = {
            'node_id':node_id
            }
    return jsonify(response), 200

        
@flask_path.route('/nodes/resolve', methods=['GET']) 
def resolve_chain():
    replaced = blockchain.resolve_longest_chain()
    msg = ''
    if replaced:
        msg = 'Longer chain found - Chain overwritten'
    else:
        msg = 'Our chain is longest - No conflict'
        
    response = {
                'replaced' : replaced,
                'message': msg
        }
    return jsonify(response), 200

if __name__ == '__main__':
    flask_path.run(host='0.0.0.0', port=5000)