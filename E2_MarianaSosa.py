from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def sign_message(private_key, message):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(public_key, signature, message):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print("Error verifying signature:", e)
        return False


def hash_file(file_path):
    with open(file_path, "rb") as file:
        file_hash = hashlib.sha256()
        while chunk := file.read(4096):
            file_hash.update(chunk)
        return file_hash.digest()


def main():
    # generar claves para Alice y la Autoridad Certificadora (AC)
    alice_private_key, alice_public_key = generate_key_pair()
    ac_private_key, ac_public_key = generate_key_pair()

    # nombre del archivo PDF
    pdf_file = "NDA.pdf"

    # firmar digitalmente el contrato por Alice
    with open(pdf_file, "rb") as file:
        pdf_hash = hash_file(pdf_file)
        signature = sign_message(alice_private_key, pdf_hash)

    # guardar la firma digital en el archivo PDF
    with open(pdf_file, "ab") as file:
        file.write(b"\n\nAlice's Digital Signature:\n")
        file.write(signature)

    # verificar la firma digital por la Autoridad Certificadora (AC)
    is_signature_valid = verify_signature(alice_public_key, signature, pdf_hash)
    if is_signature_valid:
        print("Alice's signature verified by AC.")
    else:
        print("Alice's signature not verified by AC.")

    # firmar el documento por la Autoridad Certificadora (AC)
    with open(pdf_file, "rb") as file:
        pdf_hash = hash_file(pdf_file)
        ac_signature = sign_message(ac_private_key, pdf_hash)

    # guardar la firma digital de la AC en el archivo PDF
    with open(pdf_file, "ab") as file:
        file.write(b"\n\nAC's Digital Signature:\n")
        file.write(ac_signature)

    # verificar la firma digital por Bob
    is_ac_signature_valid = verify_signature(ac_public_key, ac_signature, pdf_hash)
    if is_ac_signature_valid:
        print("AC's signature verified by Bob.")
    else:
        print("AC's signature not verified by Bob.")


if __name__ == "__main__":
    main()
