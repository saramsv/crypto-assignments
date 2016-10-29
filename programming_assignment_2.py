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
    return IV

def pad(plaintext,block_length):
    num_padzeros = len(plaintext) % block_length
    plaintext = plaintext + chr(0)*num_padzeros
    num_blocks = len(plaintext)/block_length
    message_blocks = []
    for i in range(num_blocks):
        message_blocks.append(plaintext[i*block_length:(i+1)*block_length])
    return message_blocks

def CBC_encryption(plaintext , key):
    mode = AES.MODE_ECB
    encryptor = AES.new(key)
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
        decrypted_plaintext[i] = xorWord(decryptor.decrypt(ciphertext[i]), IV)
    return decrypted_plaintext

def Dump(n):
    s = '%x' % n
    if len(s) & 1:
       s = '0' + s
    return s.decode('hex')

def CTR_encryption(plaintext, key):
    mode = AES.MODE_ECB
    encryptor = AES.new(key)
    IV = generate_iv(block_length)
    IV_init = IV
    cipher_blocks = []
    for plaintext_i in plaintext:
        cipher_blocks.append(xorWord(encryptor.encrypt(IV),plaintext_i))
        IV = binascii.hexlify(IV)
        IV = int(IV, 16) + 1
        IV = Dump(IV)
    return cipher_blocks

def to_bytes(n, length, endianess='big'): # the input number's length in bits  has to be less than block length 
    h = '%x' % n
    s = ('0'*(len(h) % 2) + h).zfill(length*2).decode('hex')
    return s if endianess == 'big' else s[::-1]

def from_bytes(n):  #n is the number that is equal to the length of the message in byte and this function gives an integer
    return int(n.encode('hex'), 16)

def CBC_mac_pad(plaintext , block_length):
    message_length = len(plaintext)
    num_padzeros = message_length % block_length
    plaintext = plaintext + chr(0)*num_padzeros
    num_blocks = int(math.ceil(message_length/float(block_length)))
    message_blocks = []
    
    M = to_bytes(message_length, block_length)
    message_blocks.append(M)

    for i in range(num_blocks):
        message_blocks.append(plaintext[i*block_length:(i+1)*block_length])
    return message_blocks


def CBC_mac(plaintext , key):
    plaintext = CBC_mac_pad(plaintext, block_length)
    mode = AES.MODE_ECB
    encryptor = AES.new(key)
    i = 0
    for plaintext_i in plaintext:
        if i == 0:
            cipher_block = encryptor.encrypt(plaintext_i)
            i = 1
        else:
             XOR_message = xorWord(plaintext_i,cipher_block)
             cipher_block = encryptor.encrypt(XOR_message)

    mac = cipher_block
    #mac = binascii.hexlify(mac)
    return mac
                
def CBC_mac_verification(message , key , tag):
    #message = CBC_mac_pad(message , block_length)
    tag_new = CBC_mac(message , key)
    if tag == tag_new:
        print "valid"
        return
    else:
        print "invalid"
        return



if __name__=='__main__':

    # Encrypt using CBC mode
    plaintext = 'sarakai_' * 15
    message_blocks = pad(plaintext,block_length)
    ciphertext,iv = CBC_encryption(message_blocks, key)
    print "{}".format(plaintext)
    print "Cipher text: {}".format(ciphertext)
    # decrypt using CBC mode
    decrypted_plaintext = CBC_decryption(ciphertext, key, iv)
    print ''.join(decrypted_plaintext)

    # Encrypt using CTR mode
    #print CTR_encryption(message_blocks, key)
    # decrypt using CTR mode
    # generating a mac and verify it
    tag = CBC_mac(plaintext , key)
    tag_ = tag
    CBC_mac_verification(plaintext , key , tag_)



