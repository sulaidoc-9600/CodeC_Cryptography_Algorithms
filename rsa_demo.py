# rsa_demo.py
# RSA key generation and small text encrypt/decrypt demo
# Requires: pip install pycryptodome

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import sys

def gen_keys(priv_file='private.pem', pub_file='public.pem', bits=2048):
    key = RSA.generate(bits)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open(priv_file, 'wb') as f:
        f.write(private_key)
    with open(pub_file, 'wb') as f:
        f.write(public_key)
    print("Keys saved:", priv_file, pub_file)

def encrypt_text(pub_file, message):
    with open(pub_file, 'rb') as f:
        pub = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(pub)
    ciphertext = cipher.encrypt(message.encode())
    print("Ciphertext (hex):", ciphertext.hex())

def decrypt_text(priv_file, cipher_hex):
    with open(priv_file, 'rb') as f:
        priv = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(priv)
    ct = bytes.fromhex(cipher_hex)
    plaintext = cipher.decrypt(ct)
    print("Plaintext:", plaintext.decode())

def usage():
    print("Usage:")
    print("  python rsa_demo.py gen")
    print("  python rsa_demo.py enc public.pem \"hello\"")
    print("  python rsa_demo.py dec private.pem <cipher_hex>")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage(); sys.exit(0)
    cmd = sys.argv[1]
    if cmd == 'gen':
        gen_keys()
    elif cmd == 'enc' and len(sys.argv) == 4:
        encrypt_text(sys.argv[2], sys.argv[3])
    elif cmd == 'dec' and len(sys.argv) == 4:
        decrypt_text(sys.argv[2], sys.argv[3])
    else:
        usage()
