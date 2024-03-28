#!/usr/bin/env python3
import base64

plaintext = open('met.bin', 'rb').read()
b64 = base64.b64encode(plaintext)
print(b64)
