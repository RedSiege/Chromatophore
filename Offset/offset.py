#!/usr/bin/env python3
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
        sys.exit("Supplied input file not found!")


def get_offsets(input_file):
    # read in our raw shellcode and get the length
    raw_sc = get_raw_sc(input_file)
    sc_len = len(raw_sc)

    offset_arr = [] # stores the calculated offsets
    remaining_idx = 1 # starts at 1 - second byte of shellcode
    previous_byte = raw_sc[0] # Store previous byte we processed.

    # Loop through remaining bytes of shellcode
    while remaining_idx < sc_len:
        # Subtract previous byte from current byte to get the offset
        current_byte = raw_sc[remaining_idx] - previous_byte

        # Add 256 if value is negative to wrap around.
        if current_byte < 0:
            current_byte = current_byte + 256

        # Add current byte of offset array
        offset_arr.append(current_byte)

        # Update previous byte to current shellcode byte
        previous_byte = raw_sc[remaining_idx]
        remaining_idx += 1

    print('unsigned char first_byte = ' + hex(raw_sc[0]) + ';')
    print('unsigned char delta[{}] = '.format(str(len(offset_arr))) + "{")
    print('{}'.format(', '.join((hex(x) for x in offset_arr))) + " };")
    print('unsigned char e[{}] = '.format(str(sc_len)) + '{ 0x00 };')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", type=str,
                        help="File containing raw shellcode. Defaults to beacon.bin.")
    
    if len(sys.argv) == 1:
        # No arguments received.  Print help and exit
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    get_offsets(args.input)


if __name__ == '__main__':
    main()
