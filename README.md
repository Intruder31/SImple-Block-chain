# Simple-Block-chain
Implement a simple block chain from scratch using python 3

Features:
1. Asymmetric cryptography to encrypt and decrpyt data in blockchain. Only the node which is mentioned as 'receiver' in JSON block will be able to decrypt the message
2. Proof of Work consensus to mine a new block
3. Register new node on network and sync details of new node across all nodes
4. Auto resolve longest chain on all nodes when new block is added
5. Get public key of the specified node
6. Get list of registered node on network

The project requires following python libraries:
1. Flask
2. Requests


Note: This project was tested and presented by running multiple instances of the program on different ports of the same system. The functionality may be further extended to having nodes in a LAN.
