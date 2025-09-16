import sys
import argparse


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


def build_template(shellcode, shellcode_length):
    with open("reverse_byte_order_template.c") as tplate:
        template = tplate.read()
        template = template.replace("###SHELLCODE_LENGTH###", str(shellcode_length))
        template = template.replace("###SHELLCODE###", shellcode)

    with open("reverse_byte_order.c", "w") as outfile:
        outfile.write(template)


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

    shellcode = get_raw_sc(args.input)
    reversed = ', '.join(hex(x) for x in shellcode[::-1])

    build_template(reversed, str(len(shellcode)))

    original_shellcode = ""
    for byte in shellcode:
        original_shellcode = original_shellcode + str(hex(byte).zfill(2)) + ", "
    original_shellcode = original_shellcode.rstrip(', ')
    print("Original shellcode:")
    print(original_shellcode)


if __name__ == '__main__':
        main()



