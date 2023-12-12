from Alice import Alice
from Bob import Bob
import glob, os

if __name__ == "__main__":
    load_keys = True
    if load_keys and os.path.exists("alice-private.pem") and os.path.exists("alice-public.pem") and os.path.exists("bob-private.pem") and os.path.exists("bob-public.pem"):
        print("Loading keys from files.")
        alice = Alice(load_keys=True)
        bob = Bob(load_keys=True)
        input("Press enter to send message from Alice to Bob.")
    else:
        alice = Alice(load_keys=False)
        input("Alice's keys generated. Press enter to generate Bob's keys.")
        bob = Bob(load_keys=False)
        input("Bob's keys generated. Press enter to send message from Alice to Bob.")
    alice.send()
    input("\nMessage sent from Alice to Bob. Press enter to receive message.")
    bob.receive()
    input("\nMessage received by Bob. Press enter to send message from Bob to Alice.")
    bob.send()
    input("\nMessage sent from Bob to Alice. Press enter to receive message.")
    alice.receive()
    choice = input("\nMessage received by Alice. Press enter to clean up, enter k to keep keys.")
    
    if choice == "k":
        print("Keys kept.")
        for f in glob.glob("*.txt"):
            os.remove(f)
        exit()
    else:
        print("Cleaning up...")
        for f in glob.glob("*.txt"):
            os.remove(f)
        for f in glob.glob("*.pem"):
            os.remove(f)
        print("Clean up complete.")
        exit()


