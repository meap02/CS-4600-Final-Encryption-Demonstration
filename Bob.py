from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import hmac

BLOCK_SIZE = 16 # Bytes

def send():
    # Load Alice's public key
    with open("alice-public.pem", "rb") as f:
        alice_public_key = RSA.import_key(f.read())
    
    # Bob reads his message from a file
    with open("bob_message.txt", "r") as f:
        message = f.read()

    print("Message: \n", message, "\n")
    
    aes_key = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(aes_key, AES.MODE_ECB)
    message = pad(message.encode(), BLOCK_SIZE)
    ciphertext = cipher.encrypt(message)


    # Bob encrypts the AES key using Bob's RSA public key
    encrypted_aes_key = PKCS1_OAEP.new(alice_public_key).encrypt(aes_key)


    # Append MAC to the encrypted message
    h = hmac.new(aes_key, digestmod=SHA256)
    h.update(message)
    signature = h.digest()

    encrypted_message = encrypted_aes_key + ciphertext

    print("Encrypted message: ", encrypted_message)
    print("Signature: ", signature)

    # Bob "sends" the encrypted message and signature to Alice
    with open("bobs_encrypted_message.txt", "wb") as f:
        f.write(encrypted_message)

    with open("bobs_signature.txt", "wb") as f:
        f.write(signature)


def receive():
    # Load Bob's private key
    with open("bob-private.pem", "rb") as f:
        bob_private_key = RSA.import_key(f.read())


    # Bob receives the encrypted message and signature
    with open("alices_encrypted_message.txt", "rb") as f:
        encrypted_message = f.read()

    with open("alices_signature.txt", "rb") as f:
        signature = f.read()

    # Bob splits the encrypted message into the AES key and the ciphertext
    encrypted_aes_key = encrypted_message[:256]
    ciphertext = encrypted_message[256:]


    # Bob decrypts the AES key using his RSA private key
    aes_key = PKCS1_OAEP.new(bob_private_key).decrypt(encrypted_aes_key)
    message = AES.new(aes_key, AES.MODE_ECB).decrypt(ciphertext)

    # Bob verifies the MAC
    h = hmac.new(aes_key, digestmod=SHA256)
    h.update(message)
    if h.digest() == signature:
        print("Message is authentic:\n", unpad(message, BLOCK_SIZE).decode())
    else:
        print("Message is not authentic")


if __name__ == "__main__":
    send()
    print("Message sent to Alice from Bob")
    try:
        print()
        receive()
    except FileNotFoundError:
        print("File not found")