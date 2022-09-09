import hashlib
import secrets
from base64 import b64encode
from base64 import b64decode
from Crypto.Cipher import ChaCha20
from ecdsa import SigningKey, NIST384p
from tinyec import registry

# Hashing of Plaintext (For Digital Signature)
def hash_SHA256(plaintext):
    hashed_string = hashlib.sha256(plaintext.encode('utf-8')).hexdigest()
    return hashed_string

# Digital Signature (ECDSA)
def generation_ecdsa():
    sk = SigningKey.generate(curve=NIST384p)
    vk = sk.verifying_key
    return sk, vk

def generate_digitalSig(hashed_string, sk, vk):
    vk.precompute()
    signature = sk.sign(hashed_string.encode())
    return signature

def verify_digitalSig(signature_hex, hashed_string, sk_hex):
    try :
        sk = SigningKey.from_string(bytes.fromhex(sk_hex), curve=NIST384p)
        vk = sk.verifying_key
        vk.verify(bytes.fromhex(signature_hex), hashed_string.encode())
        print("Signature is correct")
    except:
        print("Warning: Signature does not match")

# ECDH
def compress(pubKey):
    return hex(pubKey.x) + hex(pubKey.y % 2)[2:]

def generation_ecdh():

    curve = registry.get_curve('brainpoolP256r1')

    senderPrivKey = secrets.randbelow(curve.field.n)
    senderPubKey = senderPrivKey * curve.g
    print("\nSender:")
    print("Public key:", compress(senderPubKey))
    print("Private key:", senderPrivKey)
    receiverPrivKey = secrets.randbelow(curve.field.n)
    receiverPubKey = receiverPrivKey * curve.g
    print("\nRecipient")
    print("Public key:", compress(receiverPubKey))
    print("Private key:", receiverPrivKey)

    print("\nPublic keys exchanged out in the open (e.g. through Internet), and are used to generate a common")
    print("key. The concept is similar to how a master key is generated on the SSL/TLS protocol.")

    senderSharedKey = senderPrivKey * receiverPubKey
    print("\nSender shared key:", compress(senderSharedKey))

    receiverSharedKey = receiverPrivKey * senderPubKey
    print("Recipient shared key:", compress(receiverSharedKey))

    print("Equal shared keys:", senderSharedKey == receiverSharedKey)
    print("\nEncrypt with Recipient public key, such that only the recipient can decrypt with his private key.")
    return senderSharedKey

# Encrypt message (ChaCha20)
# Computer can only store bytes. Encoding is to turn the things to bytes which can be stored in computer.
# Shared key is a common key between alice and bob generated through Diffie-Hellman Key Exchange
def encrypt_ChaCha20(plaintext, symmetric_key):
    # Common key generated from ECDH is used as symmetric key
    # Only takes first 32 bytes of the ECDH shared key
    # symmetric_key = compress(uncompressed_sharedkey)[:32].encode() # 256-bit key = 32-byte (32 characters)
    # Nonce is randomly generated
    cipher = ChaCha20.new(key=symmetric_key)  # 96-bit nonce so 12-byte
    ciphertext = cipher.encrypt(plaintext.encode())  # must be binary string so do string.encode
    nonce = b64encode(cipher.nonce).decode('utf-8')
    ct = b64encode(ciphertext).decode('utf-8')
    #result = json.dumps({'nonce': nonce, 'ciphertext': ct})
    #print("Nonce: " + nonce + "| Ciphertext: " + ct)
    return nonce, ct
    # Return is in JSON format

# Decrypt message (ChaCha20)
def decrypt_ChaCha20(ciphertext, nonce, symmetric_key):
    try:
        #symmetric_key = compress(uncompressed_sharedkey)[:32].encode()
        #b64 = json.loads(result)
        #nonce = b64decode(b64['nonce'])
        #ciphertext = b64decode(b64['ciphertext'])
        nonce = b64decode(nonce)
        ciphertext = b64decode(ciphertext)
        cipher = ChaCha20.new(key=symmetric_key, nonce=nonce)
        pt = cipher.decrypt(ciphertext)
        print("Plaintext message: " + pt.decode("utf-8"))
    except (ValueError):
        print("Incorrect decryption: Value Error")
    except (KeyError):
        print("Incorrect decryption: Key Error")

while True:
    # Menu
    print("===============================================================================================")
    print("|                                    Hybrid Cryptosystem                                      |")
    print("===============================================================================================")
    print(" This is a pure Python demonstration of our hybrid cryptosystem concept which is to be")
    print(" implemented into cryptocurrencies and their underlying blockchain networks.")
    print()
    print(" [1] Encrypt and Digital Signature")
    print(" [2] Decrypt")
    print(" [3] Verify ECDSA Digital Signature")
    print(" [0] Exit")
    print("===============================================================================================")

    option = ""
    try:
        option = int(input("\nEnter an option: "))
    except (ValueError):
        print("Error: Option not recognised. Please enter a valid integer from 0 - 3.")
        continue

    if option == 1:

        # plaintext = 'Bob, 30, America, A+'
        plaintext = input("Enter plaintext: ")

        print("===============================================================================================")
        print("|                                    Hybrid Cryptosystem                                      |")
        print("===============================================================================================")
        # Digital Signature Creation

        # Hash
        hashed_string = hash_SHA256(plaintext)
        print("SHA256 Hash:", hashed_string)

        # Generation of ECDSA Key Pair and Signature
        ecdsa_keypair = generation_ecdsa()
        try:
            signature = generate_digitalSig(hashed_string, ecdsa_keypair[0], ecdsa_keypair[1])
            hex_signature = signature.hex()
            sk = ecdsa_keypair[0].to_string()
            print("\nDigital Signature has been successfully created.")
            print("Please take note of the following:")
            print("Digital Signature: " + hex_signature)
            print("Signing Key: " + sk.hex())
        except:
            print("\nError: Digital Signature creation is unsuccessful.")

        # Generation of ECDH Key Pair and Shared Key
        print("\nElliptic Curve Diffie–Hellman Key Exchange Output:")
        uncompressed_sharedkey = generation_ecdh()
        compressed_sharedkey = compress(uncompressed_sharedkey)[:32].encode()
        print("ECDH Shared Key (for ChaCha20 Encryption/Decryption): " + compressed_sharedkey.decode())

        # Encrypt using ChaCha20 with ECDH shared key
        print("\nChaCha20 Encryption Output:")
        chachaTuple = encrypt_ChaCha20(plaintext, compressed_sharedkey)
        print("Nonce: " + chachaTuple[0] + " Ciphertext: " + chachaTuple[1])
        print("\nFinally, the encrypted message (ciphertext) and nonce (can be a generated random number that")
        print("is sent across, eg. Client random number), will be sent across to the recipient with the digital")
        print("signature attached.")
        print("===============================================================================================")

    elif option == 2:
        ciphertext = input("Enter ciphertext: ")
        nonce = input("Enter nonce: ")
        compressed_sharedkey = input("Enter ECDH Shared Key: ").encode()

        print("===============================================================================================")
        print("|                                        Decryption                                           |")
        print("===============================================================================================")
        print("Ciphertext is decrypted using the shared secret key generated through the Elliptic Curve")
        print("Diffie–Hellman Key Exchange algorithm, using public and private keys from each other.")
        print()
        decrypt_ChaCha20(ciphertext, nonce, compressed_sharedkey)
        print("===============================================================================================")
        print()
    elif option == 3:
        signature_hex = input("Enter Signature: ")
        hashed_string = input("Enter hashed string: ")
        sk_hex = input("Enter Signing Key: ")

        verify_digitalSig(signature_hex, hashed_string, sk_hex)
    elif option == 0:
        print("Bye!")
        break
    else:
        print("Error: Option not recognised. Please enter a valid integer from 0 - 3.")

# Test decryption:
# ct: dxR3f0c=
# nonce: hEOOHyIjEqU=
# key: 0x83902a6229b040264e5412fcbf9a03

# Digital sig: bd8c981c55b898fb7b8bda1ae85b4d06699442cf7c383366075584c070ad3c45bcab847e2499e773b60d3e391c9fb764e2c4bde591570cc7db9990e0d9d2191029a9d5501c9a6133d9cc79890a23a81c0c7ad691e968c1bf8d93638848ca634d
# Sign Key: 2b99b7106522073e8760ea6727244f1989374c75eaa4cb98649af6596cd391e4e3068b278c3e21ced8751662d50d6323
# Hash: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
