#!/usr/bin/env python3
import base64
import sys
import argparse

def build_template(shellcode):
    with open("b64string_template.cs") as tplate:
        template = tplate.read()
        template = template.replace("###SHELLCODE###", shellcode)

    with open("b64string.cs", "w") as outfile:
        outfile.write(template)


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


def main():
    ### Parse our arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", type=str,
                        help="Payload to be encrypted.")

    args = parser.parse_args()
    if len(sys.argv) == 1:
        # No arguments received.  Print help and exit
        parser.print_help(sys.stderr)
        sys.exit(0)

    b64 = ""
    try:
        plaintext = open(args.input, "rb").read()
        b64 = base64.b64encode(plaintext)
    except FileNotFoundError:
        print("I couldn't find the file you specified: %s" % args.input)
        print("Exiting...\n")
        sys.exit()

    build_template(str(b64, "UTF-8"))

    raw_shellcode = get_raw_sc(args.input)
    original_shellcode = ""
    for byte in raw_shellcode:
        original_shellcode = original_shellcode + str(hex(byte).zfill(2)) + ", "
    original_shellcode = original_shellcode.rstrip(', ')
    print("Original shellcode:")
    print(original_shellcode)


if __name__ == "__main__":
    main()
