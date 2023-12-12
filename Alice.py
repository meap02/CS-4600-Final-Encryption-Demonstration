from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import hmac


class Alice:
    BLOCK_SIZE = 16 # Bytes
    message = "From Alice:\nLorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."

    def __init__(self, load_keys=False):
        if load_keys:
            self.rsa_key = self.load_keys()
        else:
            self.rsa_key = RSA.generate(2048)
            self.save_keys()
        self.aes_key = get_random_bytes(Alice.BLOCK_SIZE)
        self.cipher = cipher = AES.new(self.aes_key, AES.MODE_ECB) # Use ECB mode for simplicity

    def save_keys(self):
        with open("alice-private.pem", "wb") as f:
            f.write(self.rsa_key.export_key("PEM"))

        with open("alice-public.pem", "wb") as f:
            f.write(self.rsa_key.publickey().export_key("PEM"))
    
    def load_keys(self):
        key_pair = RSA.generate(2048)
        with open("alice-private.pem", "rb") as f:
            self.rsa_key = RSA.import_key(f.read())
        
        with open("alice-public.pem", "rb") as f:
            self.rsa_key = RSA.import_key(f.read())
        return key_pair
        

    def send(self):
        # Load Bob's public key
        with open("bob-public.pem", "rb") as f:
            bob_public_key = RSA.import_key(f.read())

        print("Message: \n", Alice.message, "\n")

        # Alice encrypts her message using AES
        
        message = pad(Alice.message.encode(), Alice.BLOCK_SIZE)
        ciphertext = self.cipher.encrypt(message)


        # Alice encrypts the AES key using Bob's RSA public key
        encrypted_aes_key = PKCS1_OAEP.new(bob_public_key).encrypt(self.aes_key)


        # Append MAC to the encrypted message
        h = hmac.new(self.aes_key, digestmod=SHA256)
        h.update(message)
        signature = h.digest()

        encrypted_message = encrypted_aes_key + ciphertext

        print("Encrypted message: ", encrypted_message)
        print("Signature: ", signature)

        # Alice "sends" the encrypted message and signature to Bob
        with open("alice_encrypted_message.txt", "wb") as f:
            f.write(encrypted_message)

        with open("alice_signature.txt", "wb") as f:
            f.write(signature)

    def receive(self):
        # Load Alice's private key
        with open("alice-private.pem", "rb") as f:
            alice_private_key = RSA.import_key(f.read())

        # Alice receives the encrypted message and signature from Bob
        with open("bob_encrypted_message.txt", "rb") as f:
            encrypted_message = f.read()

        with open("bob_signature.txt", "rb") as f:
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
            print("Message is authentic:\n", unpad(message, Alice.BLOCK_SIZE).decode())
        else:
            print("Message is not authentic")