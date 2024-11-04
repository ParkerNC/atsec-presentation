# echo-server.py

from time import sleep
import socket
from random import randrange
from tools import fastexp
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Hash import SHA256
from base64 import b64encode


class Server:
    def __init__(self) -> None:
        
        self.HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
        self.PORT = 65431  # Port to listen on (non-privileged ports are > 1023)
        self.p = 0
        self.g = 0
        self.a = 0

    def recieve_params(self, conn) -> None:
        data = conn.recv(2048)
        vals = data.decode("utf-8")
        vals = vals.split(' ')
        self.p = int(vals[0])
        self.g = int(vals[1])
        self.a = randrange(self.p)

    def send_public_key(self, conn, key) -> None:
        conn.sendall(str(key).encode("utf-8"))

    def recieve_public_key(self, conn) -> int:
        data = conn.recv(2048)
        num = int(data.decode("utf-8"))
        #print(f"Received {num}, {data}")
        return num

    def send_encrypted_message(self, conn, iv, ciphertext) -> None:
        message = f"{iv} {ciphertext}"
        conn.sendall(message.encode("utf-8"))

    def serve(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.HOST, self.PORT))
            s.listen()
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                self.recieve_params(conn)
                print(f"Recieved Parameters g:{self.g} \np:{self.p}")
                sleep(2)
                public_key = fastexp(self.g, self.a, self.p)
                self.send_public_key(conn, public_key)
                print("Calculated g^a (mod p) and sent to client")
                sleep(2)
                client_public = self.recieve_public_key(conn)
                print("Recieved public key information from client")
                sleep(2)
                key = fastexp(client_public, self.a, self.p)
                print("Computed shared key value")
                print(f"Shared Key: {key}")

                #convert numeric key into sha hash and use this as key input for aes
                inp = key.to_bytes((key.bit_length() + 7) // 8, 'big') or b'\0'
                sharedKey = SHA256.new(inp).digest()[:16]
                print(f"Hashed key: {sharedKey}")
                sleep(2)
                plaintext = b"atsec information security"
                cipher = AES.new(sharedKey, AES.MODE_CBC)
                ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
                iv = b64encode(cipher.iv).decode('utf-8')
                ciphermessage = b64encode(ciphertext).decode('utf-8')
                self.send_encrypted_message(conn, iv, ciphermessage)
                print("sent message encrypted with shared key to client")

                conn.close()

if __name__ == "__main__":
    server = Server()
    server.serve()

