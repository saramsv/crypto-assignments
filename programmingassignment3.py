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
import os
from programming_assignment_2 import CBC_mac_pad , CBC_mac , CBC_encryption , CBC_decryption, build_message_blocks, prime_test, generate_prime, RSA_padding, RSA_padding_all_blocks, pow_mod, RSA_encryption, RSA_decryption, RSA_deleting_zeros, check_relatively_prime, Ext_Euclidean, make_key_pair
import ntpath

k = open('exampleKeyOnes.txt')
key = k.read()
k.close()
key = binascii.unhexlify(key)
block_length = 16
num_bits = 1024
xorWord = lambda ss,cc: ''.join(chr(ord(s)^ord(c)) for s,c in zip(ss,cc))


ntpath.basename("a/b/c")
locker_pk = ''
locker_sk = ''
locker_N = ''
unlocker_pk = ''
unlocker_sk = ''
unlocker_N = ''

def generate_p_q(num_bits):
    p = generate_prime(num_bits)
    q = generate_prime(num_bits)
    return p, q

def RSA_key_generation(p,q, identity = 'Alice', filename = 'private_key.txt'): 
    N = p * q
    phi_N = (p - 1) * (q - 1)
    e = random.randrange(0, phi_N) # public key
    while True:
        if check_relatively_prime(e, phi_N):
            break
        else:
            e = random.randrange(0, phi_N)
    # e = 65537   
    if check_relatively_prime(e, phi_N) == False:
        print "This e doesnot work"
    d = Ext_Euclidean(e, phi_N) # private key
    # use the private key to sign the public key
    try:
        with open('private_key.txt','r') as infile: # use the private key from file to sign public key
            private_key = file.readlines()
            private_key = int(private_key, 16)
            file.close()
            signature = pow(d, private_key, N)
            signature = hex(signature)
            signature = signature[2:-1]
    except IOError: # file do not exist, use the own private key to sign public key
        signature = pow(e, d, N)
        signature = hex(signature)
        signature = signature[2:-1]
    return N, phi_N, d, e, identity, signature


def path_leaf(path):
    head, tail = ntpath.split(path)
    return tail

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

def random_symmetric_key_generator(length):
    a = binascii.b2a_hex(os.urandom(length))
    a = binascii.unhexlify(a)
    return a

def locker_key_generator(p , q):
    locker_N, phi, locker_pk, locker_sk  = make_key_pair(p, q)
    return locker_N ,locker_pk, locker_sk

def unlocker_key_generator(p , q):
    unlocker_N, phi, unlocker_pk, unlocker_sk  = make_key_pair(p, q)
    return unlocker_N , unlocker_pk, unlocker_sk
def hashing(message): 
    return hashlib.sha256(message).hexdigest()

def generate_signature(hashdata, N, d): # d is private key
    c_block = list()
    for block_i in hashdata:
        c = RSA_encryption(int(block_i,16), N, d)
        c = hex(c)
        c = c[2:-1]
        c = c.zfill(num_bits)
        c_block.append(c)
    signature =  ''.join(c_block)
    rsa_output = open('rsa_signature.txt','w')
    rsa_output.write(signature)
    rsa_output.close()
    return signature, len(c_block)

def verification(signature, num_of_blocks, N, e):
    m_block = list()
    for i in range(num_of_blocks):
        c = RSA_deleting_zeros(signature[i * num_bits : (i+1) * num_bits])
        m = RSA_decryption(int(c,16), N, e)
        m = hex(m)
        m_block.append(m[-1 - (num_bits/2-24)/8*2 : -1])
    m =  ''.join(m_block)
    m = RSA_deleting_zeros(m)
    rsa_output = open('rsa_verification.txt','w')
    rsa_output.write(m)
    rsa_output.close()
    print m
    print "The verification (decrypt using public key) message is saved in rsa_verification.txt"
    file = open('hashofdata.txt','r')
    hashdata = file.read()
    file.close()
    print hashdata
    return (('\'' + m + '\'')==('\'' + hashdata + '\''))




def lock_directory(path):
    
    files = glob.glob(path)
    # iterate over the list getting each file 
    mac_key = random_symmetric_key_generator(32)
    #mac_key = binascii.unhexlify(mac_key)
    print mac_key
    print "mac_key: "
    print len(mac_key)
    print mac_key
    sym_keys_file = open('lock/symmetric_keys.txt' , 'w')
    sym_keys_file.write(mac_key)
    sym_keys_file.write(';')
    print "sym_key: "
    print len(key)
    print key
    sym_keys_file.write(key)
    sym_keys_file.close()
    i = 1
    for fle in files:
        with open(fle) as f:
            print "file name: ", fle
            text = f.read()
            print "txt len: " , len(text)
            tag_name = 'tag_'
            tag_name += str(i)+'.txt'
            #tag_name += path_leaf(fle)
            tag_name = 'lock/' + tag_name
            text_pad = build_message_blocks(text, block_length)
            ciphertext,iv = CBC_encryption(text_pad , key)   
            print "len of Ciphers: ",len(ciphertext)
            Iv_file = open('lock/IVs.txt', 'a')#I am supposing that the file name are in order and so do the IVs
            Iv_file.write(iv)
            Iv_file.write(';')
            Iv_file.close()
            f.close()
        fi = open(fle , 'w')
        fi.write(''.join(ciphertext))
        fi.close()
        fi = open(fle , 'r')
        print "what is saved: " , len(fi.read())
        fi.close()
        tag_file = open(tag_name , 'w')
        tag_file.write(CBC_mac(''.join(ciphertext) , mac_key))
        tag_file.close()
        i = i + 1
       
    p , q = generate_p_q(num_bits)
    locker_key_generator(p , q)
    p , q = generate_p_q(num_bits)
    unlocker_key_generator(p, q)
    sym_keys_file = open('lock/symmetric_keys.txt' , 'r')
    keys = sym_keys_file.read()
    sym_keys_file.close()
    rsa_enc_using_unlocker_pk = RSA_encryption(keys , unlocker_pk, unlocker_N)
    rsa_enc_using_locker_sk = RSA_encryption(rsa_enc_using_unlocker_pk , locker_sk , locker_N)
    print rsa_enc_using_locker_sk
    rsa_dec_using_loker_pk = RSA_decryption(rsa_enc_using_locker_sk , locker_pk , locker_N)
    rsa_dec_using_unloker_sk = RSA_decryption(rsa_dec_using_loker_pk, unlocker_sk , unlocker_N)
    if rsa_dec_using_unloker_sk == keys:
        print "were equal"
    print "key: " , keys
    print "rsa_dec_using_unloker_sk: " , rsa_dec_using_unloker_sk

    '''
    hashed_keys = hashing(keys)
    hash_blocks = RSA_padding_all_blocks(int(hashed_keys , 16), num_bits/8)
    rsa_enc_unlocker_pk, a = generate_signature(hash_blocks , unlocker_N , unlocker_pk) # here i used the public key of the unlocking party
    print rsa_enc_unlocker_pk
    hashed_data = hashing(rsa_enc_unlocker_pk)
    hash_blocks = RSA_padding_all_blocks(int(hashed_data , 16), num_bits/8)
    rsa_sign_locker_sk, a = generate_signature(hash_blocks , locker_N , locker_sk) # I used the private key of the locking party
    print rsa_sign_locker_sk
    lock_data = open('lock_sig.txt' , 'w')
    lock_data.write(rsa_sign_locker_sk)
    lock_data.close()
    '''
    return

def CBC_mac_verification(message, key, tag):
    tag_new = CBC_mac(message , key)
    mes = ''
    if tag_new == tag:
        mes= 'valid tag'
    else:
        mes = 'Invalid tag'
    return mes


def list_of_files(path, base_name):
    file_names = []
    files = glob.glob(path)
    for fl in files:
        if base_name in path_leaf(fl):
            file_names.append(fl)
    return file_names

def mac_verification(path):
    sym_keys_file = open('lock/symmetric_keys.txt' , 'r')
    keys = sym_keys_file.read()
    extract_mac_key = keys.split(';')[0]
    extract_sym_key = keys.split(';')[1]
    list_of_tag_files = list_of_files(path , 'tag')
    print "list_of_tag_files: ", list_of_tag_files
    list_of_dec_files = list_of_files(path , 'file')
    print "list_of_dec_files: " , list_of_dec_files

    for i in range(len(list_of_dec_files)):
        mf = open('lock/'+path_leaf(list_of_dec_files[i]), 'r')
        message = mf.read()
        mf.close()
        name= path_leaf(list_of_dec_files[i]).split('_')[1]
        print "name: ", name
        for j in range(len(list_of_tag_files)):
            if path_leaf(list_of_tag_files[j]).split('_')[1] == name:
                t = open('lock/'+path_leaf(list_of_tag_files[j]) , 'r')
                tag = t.read()
                t.close()
                validity = CBC_mac_verification(message, extract_mac_key, tag)
                print validity
                print "len of mess: " , len(message)
                print "len of unhex mes: " , len(message)
                if validity == 'valid tag':
                    print "tag was valid"
                    iv = open('lock/IVs.txt', 'r')
                    IVs = iv.read()
                    iv.close()
                    print "iv len: ", len(IVs.split(';')[i])
                    print "encrypted message len: ", len(build_message_blocks(message, block_length))
                    decripted_file = CBC_decryption(build_message_blocks(message, block_length), extract_sym_key, IVs.split(';')[i])
                    mf = open('lock/'+path_leaf(list_of_dec_files[i]), 'w')
                    mf.write(''.join(decripted_file))
                    print "decryption has written in the file"
                    mf.close()
                    print decripted_file

                else:
                    print "This MAC is invalid and you can not decrypt the file"
    return

def unlock_directory(path):
    pass

if __name__=='__main__':
    '''
    # Problem 1:
    print "Wait for a second, the key is generated first..."
    #p,q = generate_p_q(num_bits)
    N, phi, d, e, identity, signature = RSA_key_generation(p, q)
    s_key = open('s_key.txt','w')
    s_key.write(str(N))
    s_key.write('\n')
    s_key.write(str(d))
    s_key.close()
    p_key = open('p_key.txt','w')
    p_key.write(str(N))
    p_key.write('\n')
    p_key.write(str(e))
    p_key.close()
    sig_f = open('signature.txt','w')
    sig_f.write(str(signature))
    sig_f.close()

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
        hashdata = hashing(message)
        # save the hash into file (for verification later)
        file = open('hashofdata.txt','w')
        file.write(str(hashdata))
        file.close()
        print hashdata
        hash_blocks = RSA_padding_all_blocks(int(hashdata,16), num_bits/8)
        print hash_blocks

        # 1.1 generate Signature and save it to file
        file = open('s_key.txt','r')
        [N, d] = file.readlines()
        N = int(N)
        d = int(d)
        file.close()
        signature, num_of_blocks = generate_signature(hash_blocks, N, d)
        print "\n Signature (encrypt using private key) is saved in rsa_signature.txt, public key is saved in p_key.txt and private key is saved in s_key.txt"
        
        # 1.2 verification
        ask = raw_input("Do you want to provide the data to verify via command line ('c') or from file ('f')?")
        if ask == 'c':
            ccc = raw_input("Please type in the data to verify (hex): ") 
        if ask == 'f':
            if os.path.isfile('rsa_signature.txt'):
                readin = open('rsa_signature.txt','r')
                ccc = readin.read()
                readin.close()
            else:
                print "Signature file is missing, please sign data first (Signature willl be automatically saved as a file)."
                sys.exit("Signature file is missing, please sign data first (Signature willl be automatically saved as a file).")
        file = open('p_key.txt','r')
        [N, e] = file.readlines()
        N = int(N)
        e = int(e)
        file.close()
        # start to verify 
        verify_result = verification(ccc, num_of_blocks , N, e)
        print "The verification result is: %s." % verify_result        

    if ask == 'v':  # verification mode
        ask = raw_input("Do you want to provide the data to verify via command line ('c') or from file ('f')?")
        if ask == 'c':
            ccc = raw_input("Please type in the data to verify (hex): ") 
        if ask == 'f':
            if os.path.isfile('rsa_signature.txt'):
                readin = open('rsa_signature.txt','r')
                ccc = readin.read()
                readin.close()
            else:
                print "Signature file is missing, please sign data first (Signature willl be automatically saved as a file)."
                sys.exit("Signature file is missing, please sign data first (Signature willl be automatically saved as a file).")
        file = open('p_key.txt','r')
        [N, e] = file.readlines()
        N = int(N)
        e = int(e)
        file.close()
        # start to verify 
        verify_result = verification(signature, N, d)
        print "The verification result is: %s." % verify_result  
 
   
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
   '''
    path = 'lock/*.txt'
    lock_directory(path)
    mac_verification(path)

