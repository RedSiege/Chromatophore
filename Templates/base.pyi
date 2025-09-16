import argparse
import sys


def get_shellcode(input_file):
    file_shellcode = b''
    try:
        with open(input_file, 'rb') as shellcode_file:
            file_shellcode = shellcode_file.read()
            file_shellcode = file_shellcode.strip()
            binary_code = ''
            for byte in file_shellcode:
                binary_code += "\\x" + hex(byte)[2:].zfill(2)

            raw_shellcode = "0" + ",0".join(binary_code.split("\\")[1:])


        return (file_shellcode, raw_shellcode)

    except FileNotFoundError:
        exit("\n\nThe input file you specified does not exist! Please specify a valid file path.\nExiting...\n")


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

    '''
        Read and format shellcode
    '''
    shellcode = get_shellcode(input_file)
    sc_len = len(shellcode.split(','))
    print("The original shellcode is:\n")
    print(raw_shellcode)



if __name__ == '__main__':
    main()
