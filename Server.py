#! /usr/bin/env python
import os
import time
from ast import literal_eval

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from os import urandom
import socket
import sys
import traceback
import threading
import select

SOCKET_LIST = []
TO_BE_SENT = []
SENT_BY = {}
KEYS = {}
SIGNS = {}

class Server(threading.Thread):

    def init(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.bind(('', 5535))
        self.sock.listen(2)
        SOCKET_LIST.append(self.sock)

        self.server_private_key = self.create_server_private_key()
        self.server_public_key = self.create_server_public_key()
        self.serialized_server_public_key = self.create_serialized_server_public_key()
        self.initialization_vector= os.urandom(16)

        print("Server started on port 5535")

    def create_server_private_key(self):
        # Generate local private key
        return ec.generate_private_key(ec.SECP384R1())

    def create_derived_shared_key(self, serialized_client_public_key):
        # Performs a key exchange operation using the provided algorithm with the peer’s public key.
        server_shared_key = self.server_private_key.exchange(ec.ECDH(), serialized_client_public_key)
        return HKDF(hashes.SHA256(), 32, None, b'Server shared key').derive(server_shared_key)

    def create_server_public_key(self):
        # Convert a collection of numbers into a public key
        return self.server_private_key.public_key()

    def create_serialized_server_public_key(self):
        # Allows serialization of the key data to bytes
        return self.server_public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)

    def sign(self, key, serialized_key):
        # Sign key which can be verified later by others using the public key.
        return key.sign(
            serialized_key,
            ec.ECDSA(hashes.SHA256())
        )

    def verify_key(self, key, signature, serialized_key):
        try:
            # Verify client key was signed by the private key associated with this public key.
            key.verify(
                signature,
                serialized_key,
                ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            print('Sign invalid')

    def run(self):
        while 1:
            read, write, err = select.select(SOCKET_LIST, [], [], 0)
            for sock in read:
                if sock == self.sock:
                    sockfd, addr = self.sock.accept()
                    #print(str(addr))
                    SOCKET_LIST.append(sockfd)
                    #print(SOCKET_LIST[len(SOCKET_LIST) - 1])
                    #Send serialized server public key for clients
                    sockfd.sendall(self.serialized_server_public_key)
                    #print("serialized_server_public_key - ", self.serialized_server_public_key)
                    time.sleep(1)

                else:
                    try:
                        #Client recieve data
                        s = sock.recv(1024)

                        text = "-----BEGIN PUBLIC KEY-----"
                        # Verify data is a public key
                        if s.startswith(text.encode()):
                                # Add public key client connect
                                KEYS[str(sock.getpeername())] = s
                                SIGNS[str(sock.getpeername())] = False
                                # Send client unique random bytes
                                sock.sendall(self.initialization_vector)

                                signature = self.sign(
                                    self.server_private_key,
                                    self.serialized_server_public_key)

                                # print("Sendall serialized_server_public_key", self.serialized_server_public_key)
                                sock.sendall(signature)
                        elif not SIGNS[str(sock.getpeername())]:
                            SIGNS[str(sock.getpeername())] = True
                            client_public_key = serialization.load_pem_public_key(KEYS[str(sock.getpeername())])
                            # Verify client key was signed by the private key associated with this public key.
                            self.verify_key(KEYS[str(sock.getpeername())], s, client_public_key)
                        else:
                            SIGNS[str(sock.getpeername())] = False
                            TO_BE_SENT.append(s)
                            SENT_BY[s] = (str(sock.getpeername()))

                    except:
                        print(str(sock.getpeername()))


class handle_connections(threading.Thread):

    def encrypt(self, plaintext, key, initialization_vector):
        #Algorithm block cipher standardized and mode of operation
        cipher = Cipher(algorithms.AES(key), modes.CBC(initialization_vector))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext

    def decrypt(self, ciphertext, key, initialization_vector):
        #Algorithm block cipher standardized and mode of operation
        cipher = Cipher(algorithms.AES(key), modes.CBC(initialization_vector))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext

    def run(self):

        while 1:
            read, write, err = select.select([], SOCKET_LIST, [], 0)
            for items in TO_BE_SENT:

                for s in write:
                    try:
                        print("Send to -> ", str(s.getpeername()))
                        print("Send by ->", SENT_BY[items])
                        time.sleep(0.5)

                        # If origin client and destiny is same
                        if (str(s.getpeername()) == str(SENT_BY[items])):
                            print("Ignoring %s" % (str(s.getpeername())))
                            continue

                        # Load key from origin client in PEM format
                        client_public_key = serialization.load_pem_public_key(KEYS[SENT_BY[items]])
                        # Load shared key from origin client
                        derived_shared_key = srv.create_derived_shared_key(client_public_key)
                        # Decrypt text to message by origin client
                        r_plaintext = self.decrypt(
                            items,
                            derived_shared_key,
                            srv.initialization_vector)
                        # Load key from destiny client in PEM format
                        client_public_key = serialization.load_pem_public_key(KEYS[str(s.getpeername())])
                        # Load shared key from destiny client
                        derived_shared_key = srv.create_derived_shared_key(client_public_key)
                        # Encrypt text to message by origin client
                        s_ciphertext = self.encrypt(
                            r_plaintext,
                            derived_shared_key,
                            srv.initialization_vector)
                        # Send encrypt message to destiny client
                        s.sendto(s_ciphertext, literal_eval(str(s.getpeername())))
                        print("Sending to -> ", (str(s.getpeername())))

                    except:
                        traceback.print_exc(file=sys.stdout)
                TO_BE_SENT.remove(items)
                del (SENT_BY[items])


if __name__ == '__main__':
    srv = Server()
    srv.init()
    srv.start()
    print(SOCKET_LIST)
    handle = handle_connections()
    handle.start()
