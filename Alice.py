from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import hmac

BLOCK_SIZE = 16 # Bytes

def send():
    # Load Bob's public key
    with open("bob-public.pem", "rb") as f:
        bob_public_key = RSA.import_key(f.read())

    # Alice reads her message from a file
    with open("alice_message.txt", "r") as f:
        message = f.read()

    print("Message: \n", message, "\n")


    # Alice encrypts her message using AES
    aes_key = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(aes_key, AES.MODE_ECB) # Use ECB mode for simplicity
    message = pad(message.encode(), BLOCK_SIZE)
    ciphertext = cipher.encrypt(message)


    # Alice encrypts the AES key using Bob's RSA public key
    encrypted_aes_key = PKCS1_OAEP.new(bob_public_key).encrypt(aes_key)


    # Append MAC to the encrypted message
    h = hmac.new(aes_key, digestmod=SHA256)
    h.update(message)
    signature = h.digest()

    encrypted_message = encrypted_aes_key + ciphertext

    print("Encrypted message: ", encrypted_message)
    print("Signature: ", signature)

    # Alice "sends" the encrypted message and signature to Bob
    with open("alices_encrypted_message.txt", "wb") as f:
        f.write(encrypted_message)

    with open("alices_signature.txt", "wb") as f:
        f.write(signature)

def receive():
    # Load Alice's private key
    with open("alice-private.pem", "rb") as f:
        alice_private_key = RSA.import_key(f.read())

    # Alice receives the encrypted message and signature from Bob
    with open("bobs_encrypted_message.txt", "rb") as f:
        encrypted_message = f.read()

    with open("bobs_signature.txt", "rb") as f:
        signature = f.read()

    # Alice splits the encrypted message into the AES key and the ciphertext
    encrypted_aes_key = encrypted_message[:256]
    ciphertext = encrypted_message[256:]


    # Alice decrypts the AES key using his RSA private key
    aes_key = PKCS1_OAEP.new(alice_private_key).decrypt(encrypted_aes_key)
    message = AES.new(aes_key, AES.MODE_ECB).decrypt(ciphertext)

    # Alice verifies the MAC
    h = hmac.new(aes_key, digestmod=SHA256)
    h.update(message)
    if h.digest() == signature:
        print("Message is authentic:\n", unpad(message, BLOCK_SIZE).decode())
    else:
        print("Message is not authentic")

if __name__ == "__main__":
    send()
    print("Message sent to Bob from Alice")
    try:
        print()
        receive()
    except FileNotFoundError:
        print("File not found")
    
