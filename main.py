import os
import argparse
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from PIL import Image

def derive_key(password, salt=b''):
    key = PBKDF2(password, salt, dkLen=32)  # 32 bytes for AES-256
    return key

def encrypt_image(input_path, output_path, password):
    iv = get_random_bytes(AES.block_size)
    key = derive_key(password)

    with open(input_path, 'rb') as f:
        plaintext = f.read()

    # Pad the plaintext to a multiple of AES block size (16 bytes)
    padded_plaintext = pad(plaintext, AES.block_size)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded_plaintext)

    with open(output_path, 'wb') as f:
        f.write(iv + ciphertext)

    print(f"{'-'*65}\nImage encrypted successfully!\n{'-'*65}")

def decrypt_image(input_path, output_path, password):
    with open(input_path, 'rb') as f:
        iv = f.read(AES.block_size)
        ciphertext = f.read()

    key = derive_key(password)

    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(ciphertext)

        # Unpad the decrypted data
        plaintext = unpad(decrypted_data, AES.block_size)

    except ValueError:
        print(f"{'-'*65}\nEntered password is not valid.\n{'-'*65}")


    with open(output_path, 'wb') as f:
        f.write(plaintext)

    print(f"{'-'*65}\nImage decrypted successfully!\n{'-'*65}")

def main():
    parser = argparse.ArgumentParser(description="Image Encryption and Decryption")
    parser.add_argument("mode", choices=["enc", "dec"], help="Choose mode type 'encrypt' or 'decrypt'")
    parser.add_argument("-i", "--input", metavar='', help="Input image file path")
    parser.add_argument("-o", "--output", metavar='', help="Output image file name (Including extension)")
    parser.add_argument("-p", "--password", metavar='', required=True, help="Password for encryption/decryption")
    args = parser.parse_args()

    if args.mode == "enc":
        if not os.path.exists(args.input):
            print(f"{'-'*65}\nInput file does not exist!\n{'-'*65}")
            return
        encrypt_image(args.input, args.output, args.password)
    elif args.mode == "dec":
        if not os.path.exists(args.input):
            print(f"{'-'*65}\nInput file does not exist!\n{'-'*65}")
            return
        decrypt_image(args.input, args.output, args.password)

if __name__ == "__main__":
    main()
