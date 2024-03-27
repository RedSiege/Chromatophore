'''
This script uses XOR with a multibyte key to encrypt a raw shellcode file.
'''
import sys
import argparse
	
def repeated_key_xor(input_text, key):
    """Returns message XOR'd with a key. If the message is longer
    than the key, the key will repeat.
    """
    input_text = input_text
    key = key
    len_key = len(key)
    encoded = []

    for i in range(0, len(input_text)):
        encoded.append(input_text[i] ^ key[i % len_key])
    return bytes(encoded)


def format_shellcode(encrypted_shellcode):
    # Format shellcode
    encrypted_shellcode = encrypted_shellcode
    chunked_shellcode = ""
    chunked_shellcode = [encrypted_shellcode[i:i+2] for i in range(0, len(encrypted_shellcode), 2)]
    final_shellcode = ""
    for chunk in chunked_shellcode:
        final_shellcode += "0x" + str(chunk).zfill(2) + ","

    # trim trailing comma
    final_shellcode = final_shellcode.rstrip(',')

    return final_shellcode


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

		
def DoBinary(input_file, key):
	# read our raw shellcode
    raw_sc = get_raw_sc(input_file)
	
    key_bytes = bytes(key, 'UTF8')
    encrypted_shellcode = repeated_key_xor(raw_sc, key_bytes).hex()

    final_shellcode = format_shellcode(encrypted_shellcode)
    with open('outfile.txt', 'w') as outfile:
        outfile.write(final_shellcode)
        sys.exit(0)

def main():
    ### Parse our arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-k", "--key", type=str,
                        help="Cipher key. Key should not contains spaces.")
    parser.add_argument("-i", "--input", type=str,
                        help="Payload to be encrypted.")

    args = parser.parse_args()
    if len(sys.argv) == 1:
        # No arguments received.  Print help and exit
        parser.print_help(sys.stderr)
        sys.exit(0)

    if not args.key:
        args.key = "XORKEY"

    if args.input:
        input_file = args.input
    else:
        input_file = "beacon.bin"

    shellcode = DoBinary(input_file, args.key)


if __name__ == '__main__':
        main()

