import socket
import json
import AES
import base64

key = b'\xcf*\x13\n=\x15\xdd\xcf\xb8?y00\x86\xe8k'

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('localhost', 5000))
    print("server started")

    while True:
        message, addr = server_socket.recvfrom(1024)
        message = json.loads(message.decode('utf-8'))

        Nonce = base64.b64decode(message['Nonce'])
        Message = base64.b64decode(message['Message'])
        Tag = base64.b64decode(message['Tag'])

        print(f'Server_encrypted: {message["Message"]}')

        Message = AES.decrypt(Nonce, Message, Tag, key)
        print(f"Client: {Message.decode()}")

        reply = input("Server: ")
        reply = reply.encode()
        nonce, reply, tag = AES.encrypt(reply, key)

        Reply = {
            'Message': base64.b64encode(reply).decode('utf-8'),
            'Nonce': base64.b64encode(nonce).decode('utf-8'),
            'Tag': base64.b64encode(tag).decode('utf-8')
        }

        Reply = json.dumps(Reply).encode('utf-8')
        server_socket.sendto(Reply, addr)

start_server()
