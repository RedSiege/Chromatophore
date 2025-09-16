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
        exit("\n\nThe input file you specified does not exist! Please specify a valid file path.\nExiting...\n")


def build_template(evenArray, evenArrayLength, oddArray, oddArrayLength):
    with open("twoarray_template.c") as tplate:
        template = tplate.read()
        template = template.replace("###SHELLCODE_LENGTH###", str(evenArrayLength + oddArrayLength))
        template = template.replace("###EVENS###", evenArray)
        template = template.replace("###ODDS###", oddArray)
        template = template.replace("###EVENS_LENGTH###", str(evenArrayLength))
        template = template.replace("###ODDS_LENGTH###", str(oddArrayLength))

    with open("twoarray.c", "w") as outfile:
        outfile.write(template)


def split_list(input_list):
    even_list = []
    odd_list = []

    idx = 0
    for val in input_list:
        if (idx % 2) == 0:
            even_list.append(val)
        else:
            odd_list.append(val)
        idx = idx + 1

    return even_list, odd_list


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

    evenArray = []
    oddArray = []
    evenArray,oddArray = split_list(shellcode)
    evens = ', '.join(hex(x) for x in evenArray)
    odds = ', '.join(hex(x) for x in oddArray)

    build_template(evens, len(evenArray), odds, len(oddArray))

    original_shellcode = ""
    for byte in shellcode:
        original_shellcode = original_shellcode + str(hex(byte).zfill(2)) + ", "
    original_shellcode = original_shellcode.rstrip(', ')
    print("Original shellcode:")
    print(original_shellcode)


if __name__ == '__main__':
    main()

