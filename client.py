
# echo-client.py

from random import randrange
import socket
from tools import diffe_helman_decrypt, diffe_helman_pk

class Client:
    def __init__(self) -> None:
        
        self.HOST = "127.0.0.1"  # The server's hostname or IP address
        self.PORT = 65434  # The port used by the server
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

    def send_public_key(self, s) -> None:
        public_key = diffe_helman_pk(self.p, self.a, self.g)
        #print(public_key)
        s.sendall(str(public_key).encode("utf-8"))
        return public_key

    def connect(self) -> None:

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.HOST, self.PORT))
            self.send_params(s)
            server_public = self.recieve_public_key(s)
            public_key = self.send_public_key(s)
            key = diffe_helman_decrypt(self.a, server_public, self.p)
            print(key)         


            s.close()
    


if __name__ == "__main__":
    
    client = Client()
    client.connect()