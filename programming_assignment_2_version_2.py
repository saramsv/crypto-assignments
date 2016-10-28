#!/usr/bin/env python
from Crypto.Cipher import AES
from Crypto import Random
import binascii
import struct
import math
key = '0123456789abcdef'

#IV = 16 * '\x00'
IV = Random.get_random_bytes(16) # CHECK!!

mode = AES.MODE_ECB
encryptor = AES.new(key)
block_length = 16
message= 'sarakai' # pading and creating blocks
message = message + chr(0) * (block_length - len(message))
num_block = math.ceil(len(message)/float(block_length))
message_blocks = []
cipher_blocks = []
message_blocks.append(message)
IV  = IV + chr(0) * (block_length - len(IV))

for m in message_blocks:
    xorWord = lambda ss,cc: ''.join(chr(ord(s)^ord(c)) for s,c in zip(ss,cc))
    encrypt = xorWord(message,IV)
    ciphertext = encryptor.encrypt(encrypt)
    IV = ciphertext
    cipher_blocks.append(ciphertext)
    ciphertext = binascii.hexlify(ciphertext).decode()
    print (ciphertext)
    
