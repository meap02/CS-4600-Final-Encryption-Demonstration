"""Simply to clean the directory of all .txt and .pem files."""

import os, glob

def clean_pkl():
    for f in glob.glob("*.pkl"):
        os.remove(f)

def clean_pem():
    for f in glob.glob("*.pem"):
        os.remove(f)

def clean_debug():
    for f in glob.glob("debug/alice/*"):
        os.remove(f)
    for f in glob.glob("debug/bob/*"):
        os.remove(f)
    os.rmdir("debug/alice")
    os.rmdir("debug/bob")
    os.rmdir("debug")
if __name__ == "__main__":
    clean_pkl()
    clean_pem()
    clean_debug()