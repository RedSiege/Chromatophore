#!/usr/bin/env python3

import argparse
import sys
from uuid import UUID


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


def insert_uuid(uuid):
    with open('main.c.template') as template_file:
        template = template_file.read()
        template = template.replace('###UUID###', uuid)
        return template


def bin_to_uuid(bin_file):
    # Author: Bobby Cooke (0xBoku/boku/boku7) // https://twitter.com/0xBoku // github.com/boku7 // https://www.linkedin.com/in/bobby-cooke/ // https://0xboku.com
    # Modified code from: https://blog.securehat.co.uk/process-injection/shellcode-execution-via-enumsystemlocala
    uuids = ''
    try:
        with open(bin_file, 'rb') as binfile:
            uuids = ''
            chunk = binfile.read(16)
            while chunk:
                if len(chunk) < 16:
                    padding = 16 - len(chunk)
                    chunk = chunk + (b"\x90" * padding)
                    uuids += "{}\"{}\"\n".format(' '*8,UUID(bytes_le=chunk))
                    break
                uuids += "{}\"{}\",\n".format(' '*8,UUID(bytes_le=chunk))
                chunk = binfile.read(16)
        return uuids
    except FileNotFoundError:
        exit("\nThe shellcode file you specified does not exist! Exiting...\n")


def build_template(uuids):
    with open("uuid_template.c") as tplate:
        template = tplate.read()
        template = template.replace("###UUIDS###", uuids)

    with open("uuid.c", "w") as outfile:
        outfile.write(template)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", type=str,
                        help="File containing raw shellcode.")
    
    if len(sys.argv) == 1:
        # No arguments received.  Print help and exit
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    # Parse our raw shellcode and format it to UUIDs
    uuids = bin_to_uuid(args.input)

    build_template(uuids)

    shellcode = get_raw_sc(args.input)
    original_shellcode = ""
    for byte in shellcode:
        original_shellcode = original_shellcode + str(hex(byte).zfill(2)) + ", "
    original_shellcode = original_shellcode.rstrip(', ')
    print("Original shellcode:")
    print(original_shellcode)


if __name__ == '__main__':
    main()
