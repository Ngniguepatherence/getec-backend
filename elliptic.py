from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Etape 1: Generation des cles

def generer_cles():
    private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def signer_document(private_key, document):
    signature = private_key.sign(
        document.encode('utf-8'),
        ec.ECDSA(hashes.SHA256())
    )
    return signature


def verifier_signature(public_key, signature, document):
    try:
        public_key.verify(
            signature,
            document.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except:
        return False





pri, pub = generer_cles()
signature = signer_document(pri,"ceci est un document")
print(pri, pub)
print(signature)
print(verifier_signature(pub, signature,"ceci est un document"))
