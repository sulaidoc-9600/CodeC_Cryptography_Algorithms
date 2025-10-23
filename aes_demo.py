# aes_demo.py
# Simple AES (EAX) file encrypt/decrypt demo
# Requires: pip install pycryptodome

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sys

def encrypt_file(input_path, key):
    cipher = AES.new(key, AES.MODE_EAX)
    with open(input_path, 'rb') as f:
        data = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(data)
    out_path = input_path + '.enc'
    with open(out_path, 'wb') as f:
        f.write(cipher.nonce + tag + ciphertext)
    print("Encrypted →", out_path)

def decrypt_file(enc_path, key):
    with open(enc_path, 'rb') as f:
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    out_path = enc_path.replace('.enc', '.dec')
    with open(out_path, 'wb') as f:
        f.write(data)
    print("Decrypted →", out_path)

def main():
    if len(sys.argv) < 4:
        print("Usage: python aes_demo.py <enc/dec> <file> <key_hex(32 chars)>")
        print("Example encrypt: python aes_demo.py enc secret.txt 00112233445566778899aabbccddeeff")
        return
    mode = sys.argv[1]
    path = sys.argv[2]
    key_hex = sys.argv[3]
    key = bytes.fromhex(key_hex)
    if len(key) not in (16,24,32):
        print("Key must be 16/24/32 bytes (hex).")
        return
    if mode == 'enc':
        encrypt_file(path, key)
    elif mode == 'dec':
        decrypt_file(path, key)
    else:
        print("Invalid mode. Use 'enc' or 'dec'.")

if __name__ == "__main__":
    main()
