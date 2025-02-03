from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return nonce, ciphertext, tag

def decrypt(nonce, ciphertext, tag, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext
    except ValueError:
        return None


if __name__ == '__main__':

    key = get_random_bytes(16)
    print(key)

    data = b"This is a secret message"

    nonce, ciphertext, tag = encrypt(data, key)

    decrypted_data = decrypt(nonce, ciphertext, tag, key)

    if decrypted_data:
        print("Decrypted data:", decrypted_data)
    else:
        print("Decryption failed")