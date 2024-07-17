import os
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA

def is_file_present(file_path):
    return os.path.exists(file_path) and not os.path.isdir(file_path)

def is_file_signed(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        start = data.find(b'\x30\x82')
        if start == -1:
            return False
        
        end = data.find(b'\x30\x82', start + 1)
        if end == -1:
            return False
        
        pkcs7 = data[start:end]
        
        start = pkcs7.find(b'\x30\x82')
        if start == -1:
            return False
        
        end = pkcs7.find(b'\x30\x82', start + 1)
        if end == -1:
            return False
        
        cert = pkcs7[start:end]
        
        rsa_key = RSA.import_key(cert)
        signer = pkcs1_15.new(rsa_key)
        digest = SHA256.new(data)
        signer.verify(digest, pkcs7)
        
        return True
    
    except Exception as e:
        return False

def read_last_lines(file_path, num_lines=10):
    """Read the last `num_lines` lines of a file."""
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()
        
    return ''.join(lines[-num_lines:])
