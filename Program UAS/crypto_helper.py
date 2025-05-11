from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    os.makedirs("keys", exist_ok=True)
    with open("keys/private.pem", "wb") as f:
        f.write(private_key)
    with open("keys/public.pem", "wb") as f:
        f.write(public_key)

def sign_file(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()

    digest = SHA256.new(data)

    with open("keys/private.pem", "rb") as f:
        private_key = RSA.import_key(f.read())

    signature = pkcs1_15.new(private_key).sign(digest)

    os.makedirs("signatures", exist_ok=True)
    signature_filename = os.path.basename(file_path) + ".sig"
    with open(f"signatures/{signature_filename}", "wb") as f:
        f.write(signature)

def verify_signature(file_path, signature_path):
    with open(file_path, 'rb') as f:
        data = f.read()

    with open(signature_path, 'rb') as f:
        signature = f.read()

    with open("keys/public.pem", "rb") as f:
        public_key = RSA.import_key(f.read())

    digest = SHA256.new(data)

    try:
        pkcs1_15.new(public_key).verify(digest, signature)
        return True
    except (ValueError, TypeError):
        return False
