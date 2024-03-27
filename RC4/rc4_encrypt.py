#!/usr/bin/env python3

from typing import Iterator
from base64 import b64encode
from sys import argv,exit,stderr
import argparse
import random
import string


# Based on snovvcrash RC4 encryption script: cathttps://gist.github.com/snovvcrash/3533d950be2d96cf52131e8393794d99
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

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", type=str,
                        help="File containing raw shellcode. Defaults to beacon.bin.")
    
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

    # https://stackoverflow.com/a/2257449
    key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))

    with open(args.input, 'rb') as f:
        result = encrypt(plaintext=f.read(), key=key)
    
    print('char key[] = "{}";'.format(key))
    print('char rc4[] = {{{}}};'.format(', '.join(hex(x) for x in result)))
 

if __name__ == '__main__':
    main()
