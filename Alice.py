from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import hmac, os, pickle


class Alice:
    """Alice is a class that represents Alice in the protocol."""
    BLOCK_SIZE = 16 # Bytes
    message = "From Alice:\nLorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."

    def __init__(self, load_keys=False):
        """Initializes Alice's keys and AES cipher."""
        if load_keys:
            self.rsa_key = self.load_keys()
        else:
            self.rsa_key = RSA.generate(2048)
            self.save_keys()
        self.aes_key = get_random_bytes(Alice.BLOCK_SIZE)
        self.cipher = cipher = AES.new(self.aes_key, AES.MODE_ECB) # Use ECB mode for simplicity

    def save_keys(self):
        """Saves the RSA key pair to files."""
        with open("alice-private.pem", "wb") as f:
            f.write(self.rsa_key.export_key("PEM"))

        with open("alice-public.pem", "wb") as f:
            f.write(self.rsa_key.publickey().export_key("PEM"))
    
    def load_keys(self) -> RSA.RsaKey:
        """Loads the RSA key pair from files."""
        key_pair = RSA.generate(2048)
        with open("alice-private.pem", "rb") as f:
            self.rsa_key = RSA.import_key(f.read())
        
        with open("alice-public.pem", "rb") as f:
            self.rsa_key = RSA.import_key(f.read())
        return key_pair
    
    def debug_print(self, packet):
        if not os.path.exists("debug"):
            os.mkdir("debug")
        if not os.path.exists("debug/alice"):
            os.mkdir("debug/alice")
        with open("debug/alice/encrypted_aes_key.txt", "wb") as f:
            f.write(packet["encrypted_aes_key"])
        with open("debug/alice/ciphertext.txt", "wb") as f:
            f.write(packet["ciphertext"])
        with open("debug/alice/MAC.txt", "wb") as f:
            f.write(packet["MAC"])
        

    def send(self, message=None):
        """Sends an encrypted message to Bob with a MAC signature."""
        # Load Bob's public key
        with open("bob-public.pem", "rb") as f:
            bob_public_key = RSA.import_key(f.read())

        if not message:
            message = Alice.message
        print("Message: \n", message, "\n")

        # Alice encrypts her message using AES
        message = pad(message.encode(), Alice.BLOCK_SIZE)
        ciphertext = self.cipher.encrypt(message)


        # Alice encrypts the AES key using Bob's RSA public key
        encrypted_aes_key = PKCS1_OAEP.new(bob_public_key).encrypt(self.aes_key)


        # Append MAC to the encrypted message
        h = hmac.new(self.aes_key, digestmod=SHA256)
        h.update(message)

        packet = {"encrypted_aes_key": encrypted_aes_key, 
                  "ciphertext": ciphertext,
                  "MAC": h.digest()}

        self.debug_print(packet)

        print("Encrypted message: ", packet["ciphertext"])
        print("Signature: ", packet["MAC"])

        with open("alice_encrypted_message.pkl", "wb") as f:
            pickle.dump(packet, f)

    def receive(self):
        """Receives an encrypted message from Bob and verifies the MAC."""
        # Load Alice's private key
        with open("alice-private.pem", "rb") as f:
            alice_private_key = RSA.import_key(f.read())

        # Alice receives the encrypted message and signature from Bob
        with open("bob_encrypted_message.pkl", "rb") as f:
            packet = pickle.load(f)


        # Bob splits the encrypted message into the AES key and the ciphertext
        encrypted_aes_key = packet["encrypted_aes_key"]
        ciphertext = packet["ciphertext"]
        signature = packet["MAC"]

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

if __name__ == "__main__":
    """This demo is a simple demonstration of the protocol. It creates Alice, as well as Alice's keys, and then Alice sends a message to Bob, who will receive it. Then Alice receives a message from Bob if Bob has sent one."""
    if not os.path.exists("alice-private.pem") and not os.path.exists("alice-public.pem"):
        alice = Alice(load_keys=False)
        print("Alice's keys generated.")
    else:
        alice = Alice(load_keys=True)
    if os.path.exists("bob-public.pem"):
        alice.send()
        print("Message sent from Alice to Bob.")
    else:
        print("Bob's public key not found. Waiting for Bob generate keys...")
    if os.path.exists("bob_encrypted_message.txt") and os.path.exists("bob_signature.txt"):
        alice.receive()
        print("Message from Bob received by Alice.")
    else:
        print("Bob's message not found. Waiting for Bob to send message...")