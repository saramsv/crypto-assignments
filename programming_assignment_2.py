#!/usr/bin/env python
from Crypto.Cipher import AES
from Crypto import Random
import binascii
import struct
import math
key = '0123456789abcdef'
block_length = 16
xorWord = lambda ss,cc: ''.join(chr(ord(s)^ord(c)) for s,c in zip(ss,cc))

def generate_iv(block_length):
    #IV = 16 * '\x00'
    IV = Random.get_random_bytes(block_length) # CHECK!!
    IV = binascii.hexlify(IV)
    return IV

def pad(plaintext,block_length):
    num_padzeros = len(plaintext) % block_length
    plaintext = plaintext + chr(0)*num_padzeros
    num_blocks = len(plaintext)/block_length
    message_blocks = []
    for i in range(num_blocks):
        message_blocks.append(binascii.hexlify(plaintext[i*block_length:(i+1)*block_length]))
    return message_blocks

def CBC_encryption(plaintext , key):
    mode = AES.MODE_ECB
    encryptor = AES.new(key)
    xorWord = lambda ss,cc: ''.join(chr(ord(s)^ord(c)) for s,c in zip(ss,cc))
    IV = generate_iv(block_length)  
    IV_init = IV
    cipher_blocks = []
    for plaintext_i in plaintext:
        XOR_message = xorWord(plaintext_i,IV)
        cipher_blocks.append(encryptor.encrypt(XOR_message))
        IV = cipher_blocks[-1]
    return cipher_blocks,IV_init

def CBC_decryption(ciphertext,key, IV_init):
    mode = AES.MODE_ECB
    decryptor = AES.new(key)
    decrypted_plaintext = [0]*len(ciphertext)
    for i in range(len(ciphertext)): 
        if i != 0:
            IV = ciphertext[i-1]
        else:
            IV = IV_init
        decrypted_plaintext[i] = binascii.unhexlify(xorWord(decryptor.decrypt(ciphertext[i]), IV))      
    return decrypted_plaintext

def Dump(n):
    s = '%x' % n
    if len(s) & 1:
       s = '0' + s
    return s.decode('hex')

def CTR_encryption(plaintext, key):
    mode = AES.MODE_ECB
    encryptor = AES.new(key)
    xorWord = lambda ss,cc: ''. join(chr(ord(s)^ord(c)) for s,c in zip(ss,cc))
    IV = generate_iv(block_length)
    IV_init = IV
    cipher_blocks = []
    for plaintext_i in plaintext:
        cipher_blocks.append(xorWord(encryptor.encrypt(IV),plaintext_i))
        IV = binascii.hexlify(IV)
        IV = int(IV, 16) + 1
        IV = Dump(IV)
    return cipher_blocks

                

if __name__=='__main__':

    # Encrypt using CBC mode
    plaintext = 'sarakai' * 15
    message_blocks = pad(plaintext,block_length)
    ciphertext,iv = CBC_encryption(message_blocks, key)
    # decrypt using CBC mode
    decrypted_plaintext = CBC_decryption(ciphertext, key, iv)

    # Encrypt using CTR mode
    haha = CTR_encryption(message_blocks, key)
    # decrypt using CTR mode



