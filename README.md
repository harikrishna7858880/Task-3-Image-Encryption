# Task-3-Image-Encryption
Task 3 Image Encryption  Description: The images must be encrypted in such a way that even with arbitrary access to them via the internet, the image must not be decryptable without a secure key. This project would help you delve into the basics of cybersecurity and develop your cryptography skills.



For image encryption, the goal is to secure image files so they can only be decrypted and viewed with the correct key. This can be achieved using strong cryptographic techniques, such as AES (Advanced Encryption Standard). Here's how you can create an image encryption project in Python:

Plan for Image Encryption
Step 1: Environment Setup
Install Python Libraries: Install the required dependencies using pip:

bash
Copy code
pip install pillow pycryptodome
Pillow: For handling image files.
PyCryptodome: For cryptographic functions like AES.
Step 2: Image Encryption Code
Here’s a Python script for encrypting and decrypting images:

python
Copy code
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from PIL import Image
import os

# Constants
BLOCK_SIZE = 16  # AES block size (16 bytes)
KEY_SIZE = 32  # AES-256 key size (32 bytes)

# Encryption function
def encrypt_image(input_path, output_path, key):
    # Open the image file
    with open(input_path, "rb") as img_file:
        image_data = img_file.read()

    # Create a cipher object with a random IV
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_data = cipher.encrypt(pad(image_data, BLOCK_SIZE))

    # Save the encrypted image with the IV prepended
    with open(output_path, "wb") as encrypted_file:
        encrypted_file.write(cipher.iv + encrypted_data)
    print(f"Image encrypted and saved to {output_path}")

# Decryption function
def decrypt_image(input_path, output_path, key):
    # Open the encrypted image file
    with open(input_path, "rb") as encrypted_file:
        file_data = encrypted_file.read()

    # Extract the IV and encrypted data
    iv = file_data[:BLOCK_SIZE]
    encrypted_data = file_data[BLOCK_SIZE:]

    # Create a cipher object with the extracted IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), BLOCK_SIZE)

    # Save the decrypted image
    with open(output_path, "wb") as decrypted_file:
        decrypted_file.write(decrypted_data)
    print(f"Image decrypted and saved to {output_path}")

# Generate a random AES-256 key
def generate_key():
    return get_random_bytes(KEY_SIZE)

if __name__ == "__main__":
    # Paths to image files
    original_image = "image.jpg"
    encrypted_image = "image_encrypted.enc"
    decrypted_image = "image_decrypted.jpg"

    # Generate or provide a key
    key = generate_key()
    print(f"Generated Key: {key.hex()}")

    # Encrypt and decrypt the image
    encrypt_image(original_image, encrypted_image, key)
    decrypt_image(encrypted_image, decrypted_image, key)
How It Works
AES-256-CBC Encryption:

The script uses AES in CBC mode to encrypt the binary data of the image.
A random initialization vector (IV) ensures that even identical images produce different encrypted files.
Image File Handling:

The image is read as raw binary data and padded to the AES block size.
The encrypted image includes the IV at the beginning, allowing the same IV to be used for decryption.
Decryption:

The script extracts the IV and encrypted data from the file.
It decrypts the data and removes padding to restore the original image.
Step 3: Testing
Prepare an Image: Save an image file as image.jpg in the same directory as the script.

Run the Script:

bash
Copy code
python image_encryption.py
Output:

image_encrypted.enc: The encrypted version of the image.
image_decrypted.jpg: The decrypted image, identical to the original.
Step 4: Key Management
Key Security: Store the key securely. Anyone with the key can decrypt the image.
Key Sharing: Use secure channels (e.g., encrypted email or key exchange protocols) to share keys.
Enhancements
Password-Based Key Derivation: Use a password to derive a cryptographic key using PBKDF2:

python
Copy code
from Crypto.Protocol.KDF import PBKDF2

password = "your_password"
salt = get_random_bytes(16)  # Use a random salt
key = PBKDF2(password, salt, dkLen=KEY_SIZE)
Graphical User Interface (GUI): Use a library like Tkinter or PyQt to build a user-friendly GUI for image encryption and decryption.

Compression: Compress images before encryption to reduce file size.

Cloud Integration: Store encrypted images on a cloud platform and implement decryption locally.
