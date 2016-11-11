#!/usr/bin/env python
from Crypto.Cipher import AES
from Crypto import Random
import binascii
import struct
import math
from Crypto.Hash import MD5
from Crypto.Random import random

k = open('exampleKeyOnes.txt')
key = k.read()
key = binascii.unhexlify(key)
block_length = 16
xorWord = lambda ss,cc: ''.join(chr(ord(s)^ord(c)) for s,c in zip(ss,cc))

def generate_iv(block_length):
    #IV = 16 * '\x00'
    IV = Random.get_random_bytes(block_length) # CHECK!!
    return IV

def prime_test(p):
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
            if p%i == 0:
                check = 1
        #i = i+1
        if check == 0:
            prime_number_p = prime_test(p)
            if prime_number_p == True :
                #print i
                return p

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

def generate_IV(plaintext, key):
    mode = AES.MODE_ECB
    encryptor = AES.new(key,mode)

    IV = generate_iv(block_length)
    IV_blocks = []
    IV_blocks.append(encryptor.encrypt(IV))
    
    for plaintext_i in plaintext:
        IV = binascii.hexlify(IV)
        IV = int(IV, 16) + 1
        IV = Dump(IV)
        IV_blocks.append(IV)
    return IV_blocks

def CTR_encryption(plaintext, IV_blocks):
    cipher_blocks = [0]*len(plaintext)
    for i in range(len(plaintext)):
        cipher_blocks[i] = xorWord(IV_blocks[i],plaintext[i])
    return cipher_blocks

def CTR_decryption(ciphertext, IV_blocks):
    decrypted_plaintext = [0]*len(ciphertext)
    for i in range(len(ciphertext)):
        decrypted_plaintext[i] = xorWord(ciphertext[i], IV_blocks[i])
    return decrypted_plaintext

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
    tag_new = CBC_mac(message , key)
    if binascii.unhexlify(tag) == tag_new:
        print 'valid tag'
        return
    else:
        print 'invalid tag'
        return

def Hash_and_mac(message , key):
    m = MD5.new()
    m.update(message)
    dig = m.hexdigest() #this returns 16 byte but m.digest returns 8 bytes
    mode = AES.MODE_ECB
    encryptor = AES.new(key,mode)
    tag = encryptor.encrypt(dig)
    return tag

def Hash_and_mac_verificaion(message, key, tag):
    tag_ = Hash_and_mac(message, key)
    if tag_== binascii.unhexlify(tag):
        print 'valid tag'
        return
    else:
        print 'invalid tag'
        return

def Ext_Euclidean(e, phi_N):
    u = e
    v = phi_N
    x1 = 1
    x2 = 0
    while (u ==1) == False:
        q = v/u
        r = v - q*u
        x = x2 - q*x1
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
    '''
    e = random.randrange(0, phi_N)
    while True:
        if check_relatively_prime(e, phi_N):
            break
         else:
            e = random.randrange(0, phi_N)
            print "this is e"
    print e'''
    e = 65537   
    if check_relatively_prime(e, phi_N)==False:
        print "This e doesnot work"
    d = Ext_Euclidean(e, phi_N)
    '''d = 3
    while d < phi_N:
        a = (d * e) % phi_N
        if  a == 1:
            break 
        d = d + 1'''
    return N, phi_N, d, e


def binary(num, pre, length, spacer):
    return '{0}{{:{1}>{2}}}'.format(pre, spacer, length).format(bin(num)[2:])

def RSA_padding(message, block_length,message_length_in_bit, message_length_in_each_block, number_of_blocks, randomness_length_in_each_block):
    '''
    message_length_in_bit = message.bit_length()
    message_length_in_each_block = (block_length/2 - 3) * 8  #in bits
    number_of_blocks = math.ceil(message_length_in_bit / float(message_length_in_each_block))

    randomness_length_in_each_block = block_length/2 * 8 #in bits
    '''
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

def RSA_padding_all_blocks(message , block_lenght):
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


def RSA_encryption(m, N, e):
    return pow(m, e, N)

def RSA_decryption(m, N, d):
    return pow(m, d, N)

if __name__=='__main__':

    
    # Encrypt using CBC mode
    input_file = open('exampleInputA.txt')    
    print "The default input is exampleInputA.txt, you may edit the file using your own input"
    plaintext = input_file.read()
    message_blocks = pad(plaintext,block_length)
    flag = True
    while flag:
        input_1 = raw_input("Enter 1 for CBC mode encryption or 2 for CTR mode encryption: ")
        if input_1 == '1':
            cbc = True
            while cbc:
                enc_dec = raw_input("Enter 1 for encrytion or 2 for decryption: ")
                if enc_dec == '1':
                    ciphertext,iv = CBC_encryption(message_blocks, key)
                    output_file = open('CBC_encryption.txt', 'w' )
                    ciphertext_string = ''.join(ciphertext)
                    output_file.write(binascii.hexlify(ciphertext_string))
                    print "The resulted ciphr text has been saved in CBC_ecryption.txt"
                if enc_dec == '2':
                    decrypted_plaintext = CBC_decryption(ciphertext, key, iv)
                    dec =  ''.join(decrypted_plaintext)
                    output_file = open('CBC_decryption.txt', 'w' )
                    output_file.write(dec)
                    print "The resulted plain text has been saved in CBC_decryption.txt"
                cbc_ = raw_input("Enter 'q' if you are done with CBC mode otherwise press a key: ")
                if cbc_ == 'q':
                    cbc = False

        if input_1 == '2':
            ctr = True
            while ctr:
                enc_dec = raw_input("Enter 1 for encrytion or 2 for decryption: ")
                if enc_dec == '1':
                    plaintext = input_file.read()
                    IV = generate_IV(message_blocks,key)
                    ciphertext = CTR_encryption(message_blocks, IV)
                    output_file = open('CTR_encryption.txt', 'w' )
                    ciphertext_string = ''.join(ciphertext)
                    output_file.write(binascii.hexlify(ciphertext_string))
                    print "The resulted ciphr text has been saved in CTR_ecryption.txt"
                if enc_dec == '2':
                    decrypted_plaintext = CTR_decryption(ciphertext, IV)
                    p =  ''.join(decrypted_plaintext)
                    output_file = open('CTR_decryption.txt', 'w' )
                    output_file.write(p)
                    print "The resulted plain text has been saved in CTR_decryption.txt" 
                ctr_ = raw_input("Enter 'q' if you are done with CTR mode otherwise press a key")
                if ctr_ == 'q':
                    ctr = False
            
        print 'the default input is exampleInputA.txt, you may edit the file using your own input' 
        input_2 = input("Enter 1 for CBC mac or 2 for hash and mac: ")
        if input_2 == 1:
            plaintext = input_file.read()
            tag = CBC_mac(plaintext , key)
            cbc_tag_file = open('CBC_mac.txt','w')
            cbc_tag_file.write(binascii.hexlify(tag))
            print "The resulted tag is saved in CBC_mac.txt"
            print "Enter a plain text in exampleInputA.txt and a tag to verify"
            inp = raw_input("tag in hex: ")
            tag_ = inp
            plaintext = input_file.read()
            CBC_mac_verification(plaintext , key , tag_)

        # generating a mac and verify it using Hash-and-mac
        if input_2 == 2:
            plaintext = input_file.read()
            hash_mac = open('hash_mac.txt','w')
            hash_mac.write(binascii.hexlify(Hash_and_mac(plaintext , key)))
            print "The resulted mac is saved in hash_mac.txt"
            print "Enter a message in exampleInputA.txt and a tag to verify"
            tag2 = raw_input("Tag in hex: ")
            plaintext = input_file.read()
            Hash_and_mac_verificaion(plaintext , key , tag2)
        fla = raw_input("Enter 'q' if you are done with AESs and MACs otherwise press a key to continue: ")
        if fla == 'q':
            flag = False
    print "RSA(please be patient, it may take few seconds): "
    p = generate_prime(1024)
    q = generate_prime(1024)
    print "Prime numbers (p , q): "
    print p
    print q
    N, phi, d, e = make_key_pair(p, q)
    
    message = 2345685244525255658788754244
    print 'message: {}'.format(message)
    message_blocks = RSA_padding_all_blocks(message , block_length)
    #print message_blocks
    m_block = list();
    for block_i in message_blocks:
        c = RSA_encryption(int(block_i,16), N, e)
        m = RSA_decryption(c, N, d)
        #print m
        m = hex(m)
        #print m
        m_block.append(m[-11:-1])
    m =  ''.join(m_block)
    m = int(m,16)   
    print 'The decrypted message is:' 
    print m


