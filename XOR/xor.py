import random
import string
from random import randrange
import argparse
import sys


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


def format_shellcode(encrypted_shellcode):
    # Format shellcode
    encrypted_shellcode = encrypted_shellcode
    chunked_shellcode = ""
    chunked_shellcode = [encrypted_shellcode[i:i + 2] for i in range(0, len(encrypted_shellcode), 2)]
    final_shellcode = ""
    for chunk in chunked_shellcode:
        final_shellcode += "0x" + str(chunk).zfill(2) + ","

    # trim trailing comma
    final_shellcode = final_shellcode.rstrip(',')

    return final_shellcode


def XOR(shellcode_bytes, key):
    encoded = []
    for i in range(0, len(shellcode_bytes)):
        encoded.append(shellcode_bytes[i] ^  key)
    return bytes(encoded)


def build_template(shellcode, shellcode_length, key):
    with open("xor_template.c") as tplate:
        template = tplate.read()
        template = template.replace("###SC_LENGTH###", str(shellcode_length))
        template = template.replace("###SHELLCODE###", shellcode)
        template = template.replace("###XORKEY###", str(hex(key)))

    with open("xor.c", "w") as outfile:
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

    xorkey = randrange(0, 255)
    #xorkey = bytes(xorkey, "UTF8")

    shellcode = get_raw_sc(input_file)
    xor_shellcode = XOR(shellcode, xorkey).hex()
    build_template(format_shellcode(xor_shellcode), len(shellcode), xorkey)

    original_shellcode = ""
    for byte in shellcode:
        original_shellcode = original_shellcode + str(hex(byte).zfill(2)) + ", "
    original_shellcode = original_shellcode.rstrip(', ')
    print("Original shellcode:")
    print(original_shellcode)


if __name__ == '__main__':
    main()


