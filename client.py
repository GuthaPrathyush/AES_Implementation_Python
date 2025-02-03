import socket
import AES
import json
import base64

key = b'\xcf*\x13\n=\x15\xdd\xcf\xb8?y00\x86\xe8k'


def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    while True:
        message = input("Client: ")
        message = message.encode()
        nonce, message, tag = AES.encrypt(message, key)

        message = {
            'Message': base64.b64encode(message).decode('utf-8'),
            'Nonce': base64.b64encode(nonce).decode('utf-8'),
            'Tag': base64.b64encode(tag).decode('utf-8')
        }

        message = json.dumps(message).encode('utf-8')
        client_socket.sendto(message, ('localhost', 5000))

        reply, _ = client_socket.recvfrom(1024)
        reply = json.loads(reply.decode('utf-8'))

        Nonce = base64.b64decode(reply['Nonce'])
        Message = base64.b64decode(reply['Message'])
        Tag = base64.b64decode(reply['Tag'])

        print(f'Server_encrypted: {reply["Message"]}')

        Message = AES.decrypt(Nonce, Message, Tag, key)
        print(f"Server: {Message.decode()}")


start_client()
