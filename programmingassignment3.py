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
from programming_assignment_2 import CBC_mac_pad , CBC_mac



k = open('exampleKeyOnes.txt')
key = k.read()
k.close()
key = binascii.unhexlify(key)
block_length = 16
xorWord = lambda ss,cc: ''.join(chr(ord(s)^ord(c)) for s,c in zip(ss,cc))

def build_message_blocks(plaintext, block_length): # message is padded and divided into blocks
    num_padzeros = len(plaintext) % block_length
    plaintext = plaintext + chr(0)*num_padzeros
    num_blocks = len(plaintext)/block_length
    message_blocks = []
    for i in range(num_blocks):
        message_blocks.append(plaintext[i * block_length : (i+1) * block_length])
    return message_blocks

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

def prime_test(p): # Miller-Rabin test
    s = 0
    N = p-1
    while True:
        N = N/2
        s = s + 1
        if N % 2 == 1:
            d = N
            break
    for i in range(5):
        a = random.randint(1, p-1)
        flag = False
        for r in range(s):
            if r == 0:
                w = pow(a, d, p)
                if w == 1:
                    flag = True
                    break
            q = pow(a, (2**r)*d , p)
            if q == p-1:
                flag = True
                break
    return flag

def generate_prime(num_bits):
    k = num_bits  
    i = 0
    prime_less_than_1000 = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677,683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]
    while True:
        p = random.randrange(2**(k-1),2**(k))
        check = 0
        for i in prime_less_than_1000:
            if p % i == 0:
                check = 1
        # i = i+1
        if check == 0:
            prime_number_p = prime_test(p)
            if prime_number_p == True :
                #print i
                return p

def Ext_Euclidean(e, phi_N):
    u = e
    v = phi_N
    x1 = 1
    x2 = 0
    while (u ==1) == False:
        q = v/u
        r = v - q * u
        x = x2 - q * x1
        v = u
        u = r
        x2 = x1 
        x1 = x
    return x1 % phi_N

def check_relatively_prime(a,b):
    while b: #b != 0
        a,b = b, a%b
    return a == 1

def make_key_pair(p,q): 
    N = p * q
    phi_N = (p - 1) * (q - 1)
    
    e = random.randrange(0, phi_N)
    while True:
        if check_relatively_prime(e, phi_N):
            break
        else:
            e = random.randrange(0, phi_N)
    # e = 65537   
    if check_relatively_prime(e, phi_N) == False:
        print "This e doesnot work"
    d = Ext_Euclidean(e, phi_N)
    return N, phi_N, d, e


def binary(num, pre, length, spacer):
    return '{0}{{:{1}>{2}}}'.format(pre, spacer, length).format(bin(num)[2:])

def RSA_padding(message, block_length,message_length_in_bit, message_length_in_each_block, number_of_blocks, randomness_length_in_each_block):
    # generate message bits:
    message_bits = message.zfill(message_length_in_each_block)
    #bbb = binary(message,'00000010', block_length*8 - message_length_each_block - 16, '0')
    # generate random bits:
    random_bits = []
    for i in range(randomness_length_in_each_block/8):
        numbers = range(1,255)
        r = random.choice(numbers)
        r = format(r, 'b').zfill(8) 
        random_bits.append(r)
    randomness = ''.join(random_bits)
    message_block = '0000000000000010' + randomness + '00000000' + message_bits
    a = int(message_block, 2)
    a = hex(a)[2:-1].zfill(block_length*2)
    return a

def RSA_padding_all_blocks(message , block_length):
    randomness_length_in_each_block = block_length/2 * 8 #in bits
    message_length_in_bit = message.bit_length()
    message_length_in_each_block = (block_length/2 - 3) * 8
    number_of_blocks = int(math.ceil(message_length_in_bit / float(message_length_in_each_block)))
    message_bit = format(message , 'b')
    RSA_bloks = []
    residue = message_length_in_bit - (number_of_blocks - 1) * message_length_in_each_block
    if number_of_blocks == 1:
        RSA_bloks.append(RSA_padding(message_bit, block_length, message_length_in_bit, message_length_in_each_block, number_of_blocks, randomness_length_in_each_block))
    else:   
        RSA_bloks.append(RSA_padding(message_bit[0 : residue], block_length, message_length_in_bit, message_length_in_each_block, number_of_blocks, randomness_length_in_each_block))
        for i in range(number_of_blocks - 1) :
            RSA_bloks.append(RSA_padding(message_bit[i * message_length_in_each_block + residue : (i+1) * message_length_in_each_block + residue], block_length, message_length_in_bit, message_length_in_each_block, number_of_blocks, randomness_length_in_each_block))
    return RSA_bloks


# implement modular exponentiation
def pow_mod(x, y, z):
    "Calculate (x ** y) % z efficiently."
    number = 1
    while y:
        if y & 1:
            number = number * x % z
        y >>= 1
        x = x * x % z
    return number

def RSA_encryption(m, N, e):
    return pow_mod(m, e, N)

def RSA_decryption(m, N, d):
    return pow_mod(m, d, N)


def RSA_deleting_zeros(m):
    k = 0
    for i in range(len(m)):
        if m[i] != '0' :
            k = i
            break
    m = m[k:] 
    return m

def lock_directory(path):
    files = glob.glob(path)
    # iterate over the list getting each file 
    files_content = ''
    for fle in files:
        # open the file and then call .read() to get the text 
        with open(fle) as f:
            text = f.read()
            files_content = files_content + text

    print binascii.hexlify(CBC_mac(files_content , key))
    return


if __name__=='__main__':
    '''
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
        '''

    # Problem 3
    lock_directory('/home/sara/repos/583_programming_assignment_2/lock/*.txt')
