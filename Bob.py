from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import hmac, os



class Bob:
    """Bob is a class that represents Bob in the protocol."""
    BLOCK_SIZE = 16 # Bytes
    message = "From Bob:\nLorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."

    def __init__(self, load_keys=False):
        """Initializes Bob's keys and AES cipher."""
        if load_keys:
            self.rsa_key = self.load_keys()
        else:
            self.rsa_key = RSA.generate(2048)
            self.save_keys()
        self.aes_key = get_random_bytes(Bob.BLOCK_SIZE)
        self.cipher = cipher = AES.new(self.aes_key, AES.MODE_ECB) # Use ECB mode for simplicity

    def save_keys(self):
        """Saves the RSA key pair to files."""
        with open("bob-private.pem", "wb") as f:
            f.write(self.rsa_key.export_key("PEM"))

        with open("bob-public.pem", "wb") as f:
            f.write(self.rsa_key.publickey().export_key("PEM"))
    
    def load_keys(self) -> RSA.RsaKey:
        """Loads the RSA key pair from files."""
        key_pair = RSA.generate(2048)
        with open("bob-private.pem", "rb") as f:
            self.rsa_key = RSA.import_key(f.read())
        
        with open("bob-public.pem", "rb") as f:
            self.rsa_key = RSA.import_key(f.read())
        return key_pair
        

    def send(self):
        """Sends an encrypted message to Alice with a MAC signature."""
        # Load Alices's public key
        with open("alice-public.pem", "rb") as f:
            alice_public_key = RSA.import_key(f.read())

        print("Message: \n", Bob.message, "\n")

        # Bob encrypts her message using AES
        message = pad(Bob.message.encode(), Bob.BLOCK_SIZE)
        ciphertext = self.cipher.encrypt(message)


        # Bob encrypts the AES key using Alice's RSA public key
        encrypted_aes_key = PKCS1_OAEP.new(alice_public_key).encrypt(self.aes_key)

        # Append MAC to the encrypted message
        h = hmac.new(self.aes_key, digestmod=SHA256)
        h.update(message)
        signature = h.digest()

        encrypted_message = encrypted_aes_key + ciphertext

        print("Encrypted message: ", encrypted_message)
        print("Signature: ", signature)

        # Bob "sends" the encrypted message and signature to Bob
        with open("bob_encrypted_message.txt", "wb") as f:
            f.write(encrypted_message)

        with open("bob_signature.txt", "wb") as f:
            f.write(signature)

    def receive(self):
        """Receives an encrypted message from Alice and verifies the MAC."""
        # Load Bob's private key
        with open("bob-private.pem", "rb") as f:
            bob_private_key = RSA.import_key(f.read())

        # Bob receives the encrypted message and signature from Bob
        with open("alice_encrypted_message.txt", "rb") as f:
            encrypted_message = f.read()

        with open("alice_signature.txt", "rb") as f:
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
            print("Message is authentic:\n", unpad(message, Bob.BLOCK_SIZE).decode())
        else:
            print("Message is not authentic")

if __name__ == "__main__":
    """This demo is a simple demonstration of the protocol. It creates Bob, as well as Bob's keys, and then Bob sends a message to Alice, who will receive it. Then Bob receives a message from Alice if Alice has sent one."""
    if not os.path.exists("bob-public.pem") and not os.path.exists("bob-private.pem"):
        bob = Bob(load_keys=False)
        print("Bob's keys generated.")
    else:
        bob = Bob(load_keys=True)
    if os.path.exists("alice-public.pem"):
        bob.send()
        print("Message sent from Bob to Alice.")
    else:
        print("Alice's public key not found. Waiting for Alice to generate keys...")
    if os.path.exists("alice_encrypted_message.txt") and os.path.exists("alice_signature.txt"):
        bob.receive()
        print("Message from Alice received by Bob.")
    else:
        print("Alice's message not found. Waiting for Alice to send message...")
