from Alice import Alice
from Bob import Bob
from clean import *

if __name__ == "__main__":
    """This demo is a simple demonstration of the protocol. It creates Alice and Bob, and then Alice sends a message to Bob, who receives it, and then Bob sends a message to Alice, who receives it."""
    if os.path.exists("alice-private.pem") and os.path.exists("alice-public.pem") and os.path.exists("bob-private.pem") and os.path.exists("bob-public.pem"):
        print("Loading keys from files.")
        alice = Alice(load_keys=True)
        bob = Bob(load_keys=True)
        alice_message = input("Press enter to send message from Alice to Bob. Enter a message to send a custom message.")
    else:
        alice = Alice(load_keys=False)
        input("Alice's keys generated. Press enter to generate Bob's keys.")
        bob = Bob(load_keys=False)
        alice_message = input("Bob's keys generated. Press enter to send message from Alice to Bob. Enter a message to send a custom message.")
    if alice_message != "":
        alice.send(message=alice_message)
    else:
        alice.send()
    input("\nMessage sent from Alice to Bob. Press enter to receive message.")
    bob.receive()
    bob_message = input("\nMessage received by Bob. Press enter to send message from Bob to Alice. Enter a message to send a custom message.")
    if bob_message != "":
        bob.send(message=bob_message)
    else:
        bob.send()
    input("\nMessage sent from Bob to Alice. Press enter to receive message.")
    alice.receive()
    choice = input("\nMessage received by Alice. Press enter to clean up, enter k to keep keys.")
    
    if choice == "k":
        print("Keys kept.")
        clean_pkl()
        clean_debug()
        exit()
    else:
        print("Cleaning up...")
        clean_pkl()
        clean_pem()
        clean_debug()

        print("Clean up complete.")
        exit()


