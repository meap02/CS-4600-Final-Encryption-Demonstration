import os, glob

for f in glob.glob("*.txt"):
    os.remove(f)
for f in glob.glob("*.pem"):
    os.remove(f)