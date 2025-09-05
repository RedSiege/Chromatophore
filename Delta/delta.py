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


def build_template(firstbyte, delta, shellcode_length):
    with open("delta_template.c") as tplate:
        template = tplate.read()
        template = template.replace("###SHELLCODE_LENGTH###", str(shellcode_length))
        template = template.replace("###DELTA_LENGTH###", str(shellcode_length - 1))
        template = template.replace("###FIRSTBYTE###", firstbyte)
        template = template.replace("###DELTA###", delta)

    with open("delta.c", "w") as outfile:
        outfile.write(template)


def get_offsets(shellcode):
    # read in our raw shellcode and get the length
    sc_len = len(shellcode)

    offset_arr = [] # stores the calculated offsets
    remaining_idx = 1 # starts at 1 - second byte of shellcode
    previous_byte = shellcode[0] # Store previous byte we processed.

    # Loop through remaining bytes of shellcode
    while remaining_idx < sc_len:
        # Subtract previous byte from current byte to get the offset
        current_byte = shellcode[remaining_idx] - previous_byte

        # Add 256 if value is negative to wrap around.
        if current_byte < 0:
            current_byte = current_byte + 256

        # Add current byte of offset array
        offset_arr.append(current_byte)

        # Update previous byte to current shellcode byte
        previous_byte = shellcode[remaining_idx]
        remaining_idx += 1

    first_byte = hex(shellcode[0])
    delta = '{}'.format(', '.join((hex(x) for x in offset_arr)))

    build_template(first_byte, delta, sc_len)

    #print('unsigned char first_byte = ' + hex(shellcode[0]) + ';')
    #print('unsigned char delta[{}] = '.format(str(len(offset_arr))) + "{")
    #print('{}'.format(', '.join((hex(x) for x in offset_arr))) + " };")
    #print('unsigned char e[{}] = '.format(str(sc_len)) + '{ 0x00 };')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", type=str,
                        help="File containing raw shellcode.")
    
    if len(sys.argv) == 1:
        # No arguments received.  Print help and exit
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    raw_sc = get_raw_sc(args.input)
    get_offsets(raw_sc)

    print("Original shellcode:")
    print(*(hex(x) for x in raw_sc))


if __name__ == '__main__':
    main()
