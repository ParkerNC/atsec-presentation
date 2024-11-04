
# echo-client.py

from time import sleep
from random import randrange
import socket
from tools import fastexp
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad
from base64 import b64decode

class Client:
    def __init__(self) -> None:
        
        self.HOST = "127.0.0.1"  # The server's hostname or IP address
        self.PORT = 65431  # The port used by the server
        self.p = 13306400456200772160288721147489113378667018293437640666245571086851906965522146421091848113159844868069462038292259294258339777975926320080262975136157147
        self.g = 2
        self.a = randrange(self.p)

    def send_params(self, s) -> None:

        public_params = f"{self.p} {self.g}"

        s.sendall(public_params.encode("utf-8"))
    
    def recieve_public_key(self, s) -> int:
        data = s.recv(2048)
        num = int(data.decode("utf-8"))
        #print(f"Received {num}, {data}")
        return num

    def send_public_key(self, s, key) -> None:
        #print(public_key)
        s.sendall(str(key).encode("utf-8"))
    
    def recieve_message(self, s) -> str:
        data = s.recv(2048)
        vals = data.decode("utf-8")
        vals = vals.split(" ")
        iv = b64decode(vals[0])
        ciphertext = b64decode(vals[1])
        return iv, ciphertext

    def connect(self) -> None:

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.HOST, self.PORT))
            self.send_params(s)
            print(f"Sent parameters g:{self.g} \np{self.p}")
            sleep(2)
            #recievce servers public key for later use
            server_public = self.recieve_public_key(s)
            print("recieved public key information from server")
            sleep(2)
            #send g^a mod p to the server
            public_key = fastexp(self.g, self.a, self.p)
            self.send_public_key(s, public_key)
            print("Calculated g^a (mod p) and sent to server")
            sleep(2)
            #calculate the shared key value 
            key = fastexp(server_public, self.a, self.p)
            print("Computed shared key value")
            print(f"Shared Key: {key}")         
            
            #convert numeric key into sha hash and use this as key input for aes
            inp = key.to_bytes((key.bit_length() + 7) // 8, 'big') or b'\0'
            sharedKey = SHA256.new(inp).digest()[:16]
            print(f"Hashed key: {sharedKey}")
            iv, ciphertext = self.recieve_message(s)
            print("recieved encrypted message from server, decrypting with shared key")
            print(f"encrypted message: {ciphertext}")
            sleep(2)
            cipher = AES.new(sharedKey, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
            message = pt.decode('utf-8')
            print(f"message: {message}")

            s.close()
    


if __name__ == "__main__":
    
    client = Client()
    client.connect()