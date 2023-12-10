from Crypto.PublicKey import RSA

alice_key = RSA.generate(2048)
bob_key = RSA.generate(2048)

with open("alice-private.pem", "wb") as f:
    f.write(alice_key.export_key("PEM"))

with open("alice-public.pem", "wb") as f:
    f.write(alice_key.publickey().export_key("PEM"))

with open("bob-private.pem", "wb") as f:
    f.write(bob_key.export_key("PEM"))

with open("bob-public.pem", "wb") as f:
    f.write(bob_key.publickey().export_key("PEM"))