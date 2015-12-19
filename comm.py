import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa
import socket
# import time
from select import select
import uuid
import msgpack
import asyncio
import traceback

VERSION = 0


class User:
    salt = b"no salt!"

    def __init__(self, username, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=User.salt,
            iterations=100000,
            backend=default_backend()
        )

        self.key = base64.urlsafe_b64encode(kdf.derive(password))
        print(self.key)
        f = Fernet(self.key)
        print(f)


user = User(input("Username: \n").encode('utf-8'), input("Password: \n").encode('utf-8'))


class Peer:

    def __init__(self, our_user, socket, other_uuid):
        ''' Socket connected to the peer '''
        self.socket = socket

        ''' An uuid.UUID '''
        self.other_uuid = other_uuid
        self.unpacker = msgpack.Unpacker()
        # loop = asyncio.get_event_loop()
        asyncio.ensure_future(self.handskake(our_user))

    async def read(self):
        while True:
            buf = (await self.reader.read(1024**2))

            # await loop.sock_recv(self.socket, 1024**2)
            if not buf:
                await asyncio.sleep(0.05)
                continue

            print(buf)

            self.unpacker.feed(buf)
            for o in self.unpacker:
                return o

    async def handskake(self, our_user):
        (self.reader, self.writer) = await asyncio.open_connection(sock=self.socket)
        data = msgpack.packb({"type": "handshake", "version": VERSION, "user": our_user.public_key})
        print("Executing handshake procedure")
        self.writer.write(data)
        result = await self.read()
        # if result[b'version']
        # loop.sock_recv(self.socket, 1024)


class Discover:

    def __init__(self):
        self.port = 54545

        self.listening_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.listening_socket.bind(('', self.port))
        # listening_socket.listen()
        # listening_socket.settimeout(0.4)

        self.uuid = uuid.uuid4()

        self.broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.broadcast_socket.setblocking(False)
        self._new_waiting_socket()

    def _new_waiting_socket(self):
        self.waiting_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.waiting_socket.bind(('0.0.0.0', 0))
        self.waiting_socket.setblocking(False)
        self.waiting_socket.listen(1)
        print(self.waiting_socket.getsockname())

    def ping(self):
        ''' Send a UDP ping on the local network '''

        address = ('<broadcast>', self.port)
        data = self.uuid.bytes + b":" + str(self.waiting_socket.getsockname()[1]).encode('utf-8')
        self.broadcast_socket.sendto(data, address)

    def _listen_for_connections_to_our_broadcast(self, our_user, peers):
        toread, _, _ = select([self.waiting_socket], [], [], 0)
        if len(toread) > 0:
            print("Incomming connection!")
            try:
                (conn, addr) = self.waiting_socket.accept()
                # 16 bytes for UUID
                # TODO: Robustness
                data = conn.recv(16)
                other_uuid = uuid.UUID(bytes=data)

                already_found = False
                for peer in peers:
                    if peer.other_uuid == other_uuid:
                        already_found = True

                if not already_found:
                    peers.append(Peer(our_user, conn, other_uuid))
                else:
                    conn.close()
            except Exception as e:
                traceback.print_tb(e.__traceback__)
                print("Failed to connect to Incomming connection")

    def _connect_with_other_broadcast(self, our_user, peers):
        toread, _, _ = select([self.listening_socket], [], [], 0)
        if len(toread) > 0:
            msg = self.listening_socket.recvfrom(128)
            other_data = msg[0]
            if len(other_data) >= 18:
                try:
                    other_uuid = uuid.UUID(bytes=other_data[:16])
                    other_port = int(other_data[17:].decode('utf-8'))

                    # Make sure we don't connect with ourselves
                    if other_uuid != self.uuid:
                        already_found = False
                        for peer in peers:
                            if peer.other_uuid == other_uuid:
                                already_found = True

                        if not already_found:
                            other_ip = msg[1][0]
                            print("Initiating connection with", other_ip + ":" + str(other_port))

                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(0.5)
                            sock.connect((other_ip, other_port))
                            sock.sendall(self.uuid.bytes)
                            peers.append(Peer(our_user, sock, other_uuid))
                except Exception as e:
                    traceback.print_tb(e.__traceback__)
                    print("Failed to connect")

    def listen(self, our_user, peers):
        ''' Adds new peers to the peer list '''

        self._listen_for_connections_to_our_broadcast(our_user, peers)
        self._connect_with_other_broadcast(our_user, peers)

async def find_peers():
    discover = Discover()
    peers = []
    while True:
        discover.ping()
        discover.listen(user, peers)
        # print("Peers: " + str(len(peers)))
        await asyncio.sleep(0.5)

loop = asyncio.get_event_loop()
loop.run_until_complete(find_peers())
loop.close()


while True:
    line = input("> ")
    if line.startswith("connect"):
        arg = line.split(' ')[1]
