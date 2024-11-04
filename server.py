# echo-server.py

import socket
from random import randrange
from tools import diffe_helman_decrypt, diffe_helman_pk

class Server:
    def __init__(self) -> None:
        
        self.HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
        self.PORT = 65434  # Port to listen on (non-privileged ports are > 1023)
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

    def send_public_key(self, conn) -> None:
        public_key = diffe_helman_pk(self.p, self.a, self.g)
        conn.sendall(str(public_key).encode("utf-8"))
        return public_key

    def recieve_public_key(self, s) -> int:
        data = s.recv(2048)
        num = int(data.decode("utf-8"))
        #print(f"Received {num}, {data}")
        return num


    def serve(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.HOST, self.PORT))
            s.listen()
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                self.recieve_params(conn)
                public_key = self.send_public_key(conn)
                client_public = self.recieve_public_key(conn)
                key = diffe_helman_decrypt(self.a, client_public, self.p)
                print(key)

                conn.close()

if __name__ == "__main__":
    server = Server()
    server.serve()

