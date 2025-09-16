import random
import sys
import argparse


def getShellcode(input_file):
    file_shellcode = b''
    try:
        with open(input_file, 'rb') as shellcode_file:
            file_shellcode = shellcode_file.read()
            file_shellcode = file_shellcode.strip()
            binary_code = ''
            sc_array = []

            for byte in file_shellcode:
                binary_code += "\\x" + hex(byte)[2:].zfill(2)

            raw_shellcode = "0" + ",0".join(binary_code.split("\\")[1:])
        for byte in raw_shellcode.split(','):
            sc_array.append(byte)

        return(sc_array)
    
    except FileNotFoundError:
        sys.exit("\n\nThe input file you specified does not exist! Please specify a valid file path.\nExiting...\n")


def build_template(jigsaw, positions, shellcode_length):
    with open("jigsaw_template.c") as tplate:
        template = tplate.read()
        template = template.replace("###SHELLCODE_LENGTH###", str(shellcode_length))
        template = template.replace("###JIGSAW###", jigsaw)
        template = template.replace("###POSITIONS###", positions)

    with open("jigsaw.c", "w") as outfile:
        outfile.write(template)

def generateJigsaw(shellcode):
    sc_len = len(shellcode)
    raw_positions = list(range(0,sc_len))
    random.shuffle(raw_positions)

    jigsaw = []
    for position in raw_positions:
        jigsaw.append(shellcode[position])

    jigsaw_array = ''
    jigsaw_array += ', '.join(str(byte) for byte in jigsaw)

    position_array = ''
    position_array += ', '.join(str(x) for x in raw_positions)

    return jigsaw_array, position_array


def main():
    ### Parse our arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", type=str,
                        help="File containing raw shellcode.")

    args = parser.parse_args()
    if len(sys.argv) == 1:
        # No arguments received.  Print help and exit
        parser.print_help(sys.stderr)
        sys.exit(0)

    if args.input:
        input_file = args.input
    else:
        input_file = "calc.bin"

    shellcode = getShellcode(input_file)
    jigsaw, positions = generateJigsaw(shellcode)

    build_template(jigsaw, positions, len(shellcode))

    print("Original shellcode:")
    print(*(x for x in shellcode))

if __name__ == "__main__":
    main()


