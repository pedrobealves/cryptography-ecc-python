#! /usr/bin/env python

import socket
import sys
import time
import threading
import select
import traceback

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class Server(threading.Thread):

    def initialise(self, receive):
        self.receive = receive
        self.client_private_key = self.create_client_private_key()
        self.client_public_key = self.create_client_public_key()
        self.serialized_public_key = self.create_serialized_public_key()

    def create(self, serialized_server_public_key, initialization_vector):
        self.server_public_key = self.create_server_public_key(serialized_server_public_key)
        client_shared_key = self.create_client_shared_key(self.server_public_key)
        self.client_shared_key = self.create_shared_key(client_shared_key)
        self.initialization_vector = initialization_vector


    def decrypt(self, ciphertext, key, initialization_vector):
        # Algorithm block cipher standardized and mode of operation
        cipher = Cipher(algorithms.AES(key), modes.CBC(initialization_vector))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext

    def create_client_public_key(self):
        # Convert a collection of numbers into a public key
        return self.client_private_key.public_key()

    def create_serialized_public_key(self):
        # Allows serialization of the key data to bytes
        return self.client_public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)

    def create_server_public_key(self, serialized_server_public_key):
        # Load keys in PEM format
        return serialization.load_pem_public_key(serialized_server_public_key)

    def create_client_shared_key(self, server_public_key):
        # Performs a key exchange operation using the provided algorithm with the peer’s public key.
        return self.client_private_key.exchange(ec.ECDH(), server_public_key)

    def create_client_private_key(self):
        # Generate local private key
        return ec.generate_private_key(ec.SECP384R1())

    def create_shared_key(self, client_shared_key):
        # Perform key derivation
        return HKDF(hashes.SHA256(), 32, None, b'Server shared key').derive(client_shared_key)


    def unpadding(self, plaintext):
        unpadder = padding.PKCS7(128).unpadder()
        #Returns the data that was unpadded.
        data = unpadder.update(plaintext)
        return (data + unpadder.finalize())

    def run(self):
        lis = []
        lis.append(self.receive)
        while 1:
            read, write, err = select.select(lis, [], [])
            for item in read:
                try:
                    # Receives clients data from server
                    s = item.recv(1024)
                    if s != '':
                        chunk = s
                        # Decrypt data receive with client shared key and initialization_vector
                        r_plaintext = self.decrypt(chunk, self.client_shared_key, self.initialization_vector)
                        plaintext = self.unpadding(r_plaintext)
                        print(plaintext.decode() + '\n>>')
                except:
                    traceback.print_exc(file=sys.stdout)
                    break


class Client(threading.Thread):
    def connect(self, host, port):
        self.sock.connect((host, port))

    def padding(self, plaintext):
        # Padding data to multiple
        padder = padding.PKCS7(128).padder()
        #Returns the data that was padded
        padded_data = padder.update(plaintext)
        return (padded_data + padder.finalize())

    def encrypt(self, plaintext, key, initialization_vector):
        #Algorithm block cipher standardized and mode of operation
        cipher = Cipher(algorithms.AES(key), modes.CBC(initialization_vector))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext

    def client(self, host, port, msg):
        sent = self.sock.send(msg)
        # print("Sending -> ", msg)
        # print "Sent\n"

    def verify_key(self, key, signature, serialized_key):
        try:
            # Verify client key was signed by the private key associated with this public key.
            key.verify(
                signature,
                serialized_key,
                ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            print('Sign invalid')

    def sign(self, key, serialized_key):
        # Sign key which can be verified later by others using the public key.
        return key.sign(
            serialized_key,
            ec.ECDSA(hashes.SHA256())
        )


    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            # host = input("Enter the server IP \n>>")
            # port = int(input("Enter the server Destination Port\n>>"))
            host = "127.0.0.1"
            port = 5535
        except EOFError:
            print("Error")
            return 1

        print("Connecting\n")
        s = ''
        self.connect(host, port)
        print("Connected\n")
        user_name = input("Enter the User Name to be Used\n>>")
        receive = self.sock
        time.sleep(0.5)
        srv = Server()

        srv.initialise(receive)


        #Receive serialized server public key
        serialized_server_public_key = receive.recv(1024)
        time.sleep(1)

        # Send serialized server public key to server
        self.client(host, port, srv.serialized_public_key)

        #Receive initialization_vector from server for CBC mode in AES algorithm
        initialization_vector = receive.recv(16)
        #print("Receive initialization_vector", initialization_vector)

        srv.create(serialized_server_public_key, initialization_vector)

        signature = receive.recv(1024)
        #print("assinatura - ", signature)

        self.verify_key(srv.server_public_key, signature, serialized_server_public_key)

        signature = self.sign(srv.client_private_key, srv.serialized_public_key)

        self.client(host, port, signature)

        srv.daemon = True
        print("Starting service")
        srv.start()


        while 1:
            # print "Waiting for message\n"
            msg = input('>>')
            if msg == 'exit':
                break
            if msg == '':
                continue
            # print "Sending\n"
            msg = user_name + ': ' + msg
            data = msg.encode()
            #Encrypt message with shared key client and initialization_vector
            s_ciphertext = self.encrypt(self.padding(data), srv.client_shared_key, initialization_vector)

            #Send encrypt message to server
            self.client(host, port, s_ciphertext)
        return (1)


if __name__ == '__main__':
    print("Starting client")
    cli = Client()
    cli.start()
