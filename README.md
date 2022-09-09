# Hybrid Cryptosystem
A hybrid cryptosystem that consists of SHA-256, ChaCha20, and ECDS, which helps to secure the transmission of data on a cryptocurrency’ underlying blockchain network which may involve application data as in the case of dApps such as radicle.xyz on Ethereum and Cardano Wall on Cardano. This allows blockchain networks to benefit from both the convenience and security of an asymmetric cryptosystem, as well as the efficiency of a symmetric algorithm for encryption of large data, which is paramount for cryptocurrencies where transaction speed is of utmost importance. 

## Contributors
This project would not be possible without the help of E Kai, Sherman, and Jonse, which was made as part of Ngee Ann Poly's assignment requirment. 

## Prerequisites

Please ensure Python and the following Python modules are installed before running the code:
- ecdsa
- tinyec
- pycryptodome

The modules can be installed by running the pip command. (eg. pip install tinyec)

## Operating Instructions

Encryption:
1) Execute the program either through python on termina/command prompt or an IDE of choice.
2) Select an option by entering an integer from 0 to 3.
3) To encrypt a plaintext message, enter the option number 1, then enter the plaintext.
4) A list of values will be generated and displayed, do take note of the following for decryption later:
- ECDH Shared Key (for ChaCha20 Encryption/Decryption)
- ChaCha20 Nonce
- Ciphertext
5) Moreover, do take note of the following values as well, for verification of the digital siganture.
- Digital signature
- Signing Key
- SHA256 Hash
6) A ciphertext and a digtal signature are generated, which can then be sent over insecure communication channels.

Decryption:
1) Execute the program either through python on termina/command prompt or an IDE of choice.
2) To decrypt a ciphertext generated using the same hybrid cryptosystem, enter option number 2.
3) Enter the ciphertext.
4) Enter the nonce.
5) Enter the ECDH shared key.
6) The ciphertext is decrypted to form the plaintext.

Verify Digital Signature
1) Execute the program either through python on termina/command prompt or an IDE of choice.
2) To verify a digital signature generated from the Encryption step as mentioned above, using the same hybrid cryptosystem, enter option number 3.
3) Enter the digital signature.
4) Enter the SHA256 hash of the plaintext generated in the Encryption step.
5) Enter the signing key.
6) The digital signature will be compared against the SHA256 hash, if they match, the program will prompt that the "Signature is correct". Otherwise,
a warning is displayed, "Warning: Signature does not match".

-- Take Note --

All output are displayed within the command prompt itself, no external files are generated.
