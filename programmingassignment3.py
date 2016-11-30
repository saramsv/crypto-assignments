#!/usr/bin/env python
from Crypto.Cipher import AES
from Crypto import Random
import binascii
import struct
import math
from Crypto.Hash import MD5
from Crypto.Random import random
import hashlib
import os.path
import sys
import glob
from programming_assignment_2 import CBC_mac_pad , CBC_mac , CBC_encryption , CBC_decryption, build_message_blocks, prime_test, generate_prime, make_key_pair, RSA_padding, RSA_padding_all_blocks, pow_mod, RSA_encryption, RSA_decryption, RSA_deleting_zeros, check_relatively_prime, Ext_Euclidean 
import ntpath
ntpath.basename("a/b/c")



def path_leaf(path):
    head, tail = ntpath.split(path)
    return tail

k = open('exampleKeyOnes.txt')
key = k.read()
k.close()
key = binascii.unhexlify(key)
block_length = 16
xorWord = lambda ss,cc: ''.join(chr(ord(s)^ord(c)) for s,c in zip(ss,cc))

def Dump(n):
    s = '%x' % n
    if len(s) & 1:
       s = '0' + s
    return s.decode('hex')

def to_bytes(n, length, endianess='big'): # the input number's length in bits has to be less than block length 
    h = '%x' % n
    s = ('0'*(len(h) % 2) + h).zfill(length*2).decode('hex')
    return s if endianess == 'big' else s[::-1]

def from_bytes(n):  #n is the number that is equal to the length of the message in byte and this function gives an integer
    return int(n.encode('hex'), 16)

def binary(num, pre, length, spacer):
    return '{0}{{:{1}>{2}}}'.format(pre, spacer, length).format(bin(num)[2:])

def lock_directory(path):
    files = glob.glob(path)
    # iterate over the list getting each file 
    for fle in files:
        with open(fle) as f:
            text = f.read()
            tag_name = 'tag_'
            tag_name += path_leaf(fle)
            tag_name = 'lock/' + tag_name
            text_pad = build_message_blocks(text, block_length)
            ciphertext,iv = CBC_encryption(text_pad , key)
            tag_file = open(tag_name , 'w')
            tag_file.write(CBC_mac(text , key))
            tag_file.close()
            f.close()
        fi = open(fle , 'w')
        fi.write(''.join(ciphertext))
        f.close()
    return

if __name__=='__main__':
    
    # Problem 1:
    print "Wait for a second, the key is generated first..."
    num_bits = 1024
    p = generate_prime(num_bits)
    q = generate_prime(num_bits) 
    N, phi, d, e = make_key_pair(p, q)
    p_key = open('s_key.txt','w')
    p_key.write(str(N))
    p_key.write('\n')
    p_key.write(str(e))
    p_key.close()
    s_key = open('p_key.txt','w')
    s_key.write(str(N))
    s_key.write('\n')
    s_key.write(str(d))
    s_key.close()

    ask = raw_input("Enter 's' for signing mode, 'v' for verification mode: ")
    if ask == 's': # signing mode
        # provide data to sign       
        ask = raw_input("Do you want to provide the data to sign via command line ('c') or from file ('f')?")
        if ask == 'c':
            message = raw_input("Please type in the data to sign (hex): ") 
        if ask == 'f':
            readin = open('datatosign.txt','r')
            message = readin.read()
            readin.close()
        # compute hash H(message)
        hashdata = hashlib.sha256(message).hexdigest()
        # save the hash into file (for verification later)
        file = open('hashofdata.txt','w')
        file.write(hashdata)
        file.close()
        # sign data
        c = RSA_encryption(int(hashdata,16), N, e)
        c = hex(c)
        c = c[2:-1]
        # save signature
        rsa_output = open('rsa_signature.txt','w')
        rsa_output.write(c)
        rsa_output.close()
        print "\n Signature (encrypt using private key) is saved in rsa_signature.txt, public key is saved in p_key.txt and private key is saved in s_key.txt"
        
        ask = raw_input("Do you want to provide the data to verify via command line ('c') or from file ('f')?")
        if ask == 'c':
            c = raw_input("Please type in the data to verify (hex): ") 
        if ask == 'f':
            if os.path.isfile('rsa_signature.txt'):
                readin = open('rsa_signature.txt','r')
                c = readin.read()
                readin.close()
            else:
                print "Signature file is missing, please sign data first."
                sys.exit("Signature file is missing, please sign data first.")
        file = open('p_key.txt','r')
        [N,d] = file.readlines()
        file.close()
        c = int(c,16)
        N = int(N)
        d = int(d)
        m = RSA_decryption(c, N, d)
        m = hex(m)
        m = m[2:-1]
        # m = RSA_deleting_zeros(m)
        rsa_output = open('rsa_verification.txt','w')
        rsa_output.write(m)
        rsa_output.close()
        print "The verification (decrypt using public key) message is saved in rsa_verification.txt"
        file = open('hashofdata.txt','r')
        hashdata = file.read()
        file.close()
        print "The verification result is: "
        print (('\'' + m + '\'')==('\'' + hashdata + '\''))
    if ask == 'v':  # verification mode
        ask = raw_input("Do you want to provide the data to verify via command line ('c') or from file ('f')?")
        if ask == 'c':
            c = raw_input("Please type in the data to verify (hex): ") 
        if ask == 'f':
            if os.path.isfile('rsa_signature.txt'):
                readin = open('rsa_signature.txt','r')
                c = readin.read()
                readin.close()
            else:
                print "Signature file is missing, please sign data first."
                sys.exit("Signature file is missing, please sign data first.")
        file = open('p_key.txt','r')
        [N,d] = file.readlines()
        file.close()
        c = int(c,16)
        N = int(N)
        d = int(d)
        m = RSA_decryption(c, N, d)
        m = hex(m)
        m = m[2:-1]
        # m = RSA_deleting_zeros(m)
        rsa_output = open('rsa_verification.txt','w')
        rsa_output.write(m)
        rsa_output.close()
        print "The verification (decrypt using public key) message is saved in rsa_verification.txt"
        print m
        print type(m)
        file = open('datatosign.txt','r')
        hashdata = file.read()
        file.close()
        print hashdata
        print type(hashdata)
        print "The verification is: "
        print (('\'' + m + '\'')==('\'' + hashdata + '\''))
        

    # Problem 3
    path = '/home/sara/repos/583_programming_assignment_2/lock/*.txt'
    print "The default directory contains some text files in hex format and the default key is exampleKeyOnes.txt and they will be used if you use the default mode \n"
    print "Lock mode \n"
    lock_unlock = raw_input("Enter 'd' for using the default parameters or 'o' for entering new parameters: ")
    if lock_unlock == 'd':
        lock_directory(path)
    elif lock_unlock == 'o':
        lock = raw_input("Enter a path to a directory such as /home/*.txt: ")
        path = lock
        k = raw_input("Enter a file name containing the key in hex format: ")
        k = open(k)
        key = k.read()
        k.close()
        key = binascii.unhexlify(key) 
        lock_directory(path)
    else:
        print "You entered a wrong character"












