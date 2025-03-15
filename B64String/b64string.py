#!/usr/bin/env python3
import base64
import sys

try:
    plaintext = open(sys.argv[1], "rb").read()
except:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit()

b64 = base64.b64encode(plaintext)

with open('b64.txt', 'w') as outfile:
    outfile.write(str(b64, 'utf-8'))
