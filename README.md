# CodeC_Cryptography_Algorithms
Author: Sulaiman  
Organization: CodeC Technologies — Cyber Security Internship

## Overview
This repository contains small demo implementations for:
- AES (symmetric encryption) — `aes_demo.py`
- RSA (asymmetric encryption) — `rsa_demo.py`

These scripts demonstrate basic encryption/decryption operations for educational and documentation purposes.

## Requirements
- Python 3.8+
- PyCryptodome: `pip install pycryptodome`

## AES demo (aes_demo.py)
Usage:

python aes_demo.py enc secret.txt 00112233445566778899aabbccddeeff
python aes_demo.py dec secret.txt.enc 00112233445566778899aabbccddeeff

Key must be provided as hex (16/24/32 bytes).

## RSA demo (rsa_demo.py)
Generate keys:

# python rsa_demo.py gen
Encrypt:

# python rsa_demo.py enc public.pem "hello"
Decrypt:

# python rsa_demo.py dec private.pem <cipher_hex>

## Notes
- These demos are for learning and documentation. For production systems use secure key management and proper libraries.
- Report: `Cryptography_Report_2Page_Sulaiman.pdf`
