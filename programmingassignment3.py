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

key2 = ''
locker_N = 0 
locker_pk = 0
locker_sk = 0
unlocker_N = 0 
unlocker_pk = 0
unlocker_sk = 0
  
people = []   
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

def assigning_keys(p,q, identity = 'Alice'): 
    N = p * q
    phi_N = (p - 1) * (q - 1)
    e = random.randrange(0, phi_N) # public key
    while True:
        if check_relatively_prime(e, phi_N):
            break
        else:
            e = random.randrange(0, phi_N)
    if check_relatively_prime(e, phi_N) == False:
        print "This e doesnot work"
    d = Ext_Euclidean(e, phi_N) # private key
    p = {"identity":identity, "public_key": e, "private_key": d, "order": N}
    people.append(p)
    return e , d, N

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

def locker_key_generator(p, q, identity):
    global locker_N, locker_pk, locker_sk, unlocker_sk, unlocker_pk, unlocker_N
    locker_pk, locker_sk, locker_N = assigning_keys(p , q, identity)
    #return locker_N ,locker_pk, locker_sk

def unlocker_key_generator(p, q, identity):
    global locker_N, locker_pk, locker_sk, unlocker_sk, unlocker_pk, unlocker_N
    unlocker_pk, unlocker_sk, unlocker_N = assigning_keys(p , q, identity)
    #return unlocker_N ,unlocker_pk, unlocker_sk

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
        c = RSA_deleting_zeros_patch(signature[i * num_bits : (i+1) * num_bits])
        m = RSA_decryption(int(c,16), N, e)
        m = hex(m)
        m_block.append(m[-1 - (num_bits/2-24)/8*2 : -1])
    m =  ''.join(m_block)
    m = RSA_deleting_zeros_patch(m)
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

def RSA_deleting_zeros_patch(m):
    res = RSA_deleting_zeros(m)
    
    if len(res) % 2 != 0:
        res = '0' + res
    if len(res) == 62:
        res = '00' + res
    return res

def RSA_encryption_supp_blocks(message, num_bits, N, d):
    message = int(message, 16)
    message_blocks = RSA_padding_all_blocks(message , num_bits/8)
    c_block = list()
    for block_i in message_blocks:
        c = RSA_encryption(int(block_i,16), N, d)
        c = hex(c)
        c = c[2:-1]
        c = c.zfill(num_bits)
        c_block.append(c)
    c_block_join =  ''.join(c_block)
    return c_block_join, len(message_blocks)
  
def RSA_decryption_supp_blocks(c_block, num_blocks, num_bits, N, e):
    m_block = list()
    for i in range(num_blocks):
        c = RSA_deleting_zeros_patch(c_block[i * num_bits : (i+1) * num_bits])
        c = int(c, 16)
        m = RSA_decryption(c, N, e)
        m = hex(m)
        m_block.append(m[-1 - (num_bits/2-24)/8*2 : -1])
    m = ''.join(m_block)
    m = RSA_deleting_zeros_patch(m)
    return m


def lock_directory(path):
    global locker_N, locker_pk, locker_sk, unlocker_sk, unlocker_pk, unlocker_N
    
    files = glob.glob(path)
    # iterate over the list getting each file 
    mac_key = random_symmetric_key_generator(32)
    sym_keys_file = open('lock/symmetric_keys.txt' , 'w')
    sym_keys_file.write(mac_key)

    sym_keys_file.write(';')
    sym_keys_file.write(key)
    sym_keys_file.close()

    i = 1
    for fle in files:
        with open(fle) as f:
            #print "file name: ", fle
            text = f.read()
            #print "txt len: " , len(text)
            tag_name = 'tag_'
            tag_name += str(i)+'.txt'
            #tag_name += path_leaf(fle)
            tag_name = 'lock/' + tag_name
            text_pad = build_message_blocks(text, block_length)
            ciphertext,iv = CBC_encryption(text_pad , key)   
            #print "len of Ciphers: ",len(ciphertext)
            Iv_file = open('lock/IVs.txt', 'a')#I am supposing that the file name are in order and so do the IVs
            Iv_file.write(iv)
            Iv_file.write(';')
            Iv_file.close()
            f.close()
        fi = open(fle , 'w')
        fi.write(''.join(ciphertext))
        fi.close()
        fi = open(fle , 'r')
        #print "what is saved: " , len(fi.read())
        fi.close()
        tag_file = open(tag_name , 'w')
        tag_file.write(CBC_mac(''.join(ciphertext) , mac_key))
        tag_file.close()
        i = i + 1
    print "For each file a tag is created"
    sym_keys_file = open('lock/symmetric_keys.txt' , 'r')
    keys = sym_keys_file.read()
    sym_keys_file.close()
    #print keys

    rsa_enc_using_unlocker_pk1, num_blocks11 = RSA_encryption_supp_blocks(binascii.hexlify(keys.split(';')[0]) , num_bits, unlocker_N, unlocker_pk) 
    rsa_enc_using_unlocker_pk2, num_blocks12 = RSA_encryption_supp_blocks(binascii.hexlify(keys.split(';')[1]) , num_bits, unlocker_N, unlocker_pk) 
        
    rsa_enc_using_locker_sk1, num_blocks21 = RSA_encryption_supp_blocks(rsa_enc_using_unlocker_pk1, num_bits, locker_N , locker_sk)
    rsa_enc_using_locker_sk2, num_blocks22 = RSA_encryption_supp_blocks(rsa_enc_using_unlocker_pk2, num_bits, locker_N , locker_sk)

    #print num_blocks11, num_blocks12, num_blocks21, num_blocks22
    file_name = 'lock/symmetric_keys.txt'
    sym_keys_file = open( file_name, 'w')
    sym_keys_file.write(rsa_enc_using_locker_sk1)
    sym_keys_file.write(';')
    sym_keys_file.write(rsa_enc_using_locker_sk2)
    sym_keys_file.write(';')
    sym_keys_file.write(hex(num_blocks11))
    sym_keys_file.write(';')
    sym_keys_file.write(hex(num_blocks12))
    sym_keys_file.write(';')
    sym_keys_file.write(hex(num_blocks21))
    sym_keys_file.write(';')
    sym_keys_file.write(hex(num_blocks22))
    sym_keys_file.close()
    print "Encrypted symmetric keys are saved in 'lock/symmetric_keys.txt'"
    return file_name

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

def del_auxiliary_files():
    print 'Deleting auxiliary files'
    aux_files = ['lock/IVs.txt', 'lock/symmetric_keys.txt'] + glob.glob('lock/tag_*')
    for f in aux_files:
        try:
            os.remove(f)
        except OSError:
            pass


def mac_verification(filename, path):
    print "Verifying tags..."
    sym_keys_file = open(filename , 'r')
    keys = sym_keys_file.read()
    extract_mac_key = keys.split(';')[0]
    extract_sym_key = keys.split(';')[1]

    list_of_tag_files = list_of_files(path , 'tag')
    #print "list_of_tag_files: ", list_of_tag_files
    list_of_dec_files = list_of_files(path , 'file')
    #print "list_of_dec_files: " , list_of_dec_files

    for i in range(len(list_of_dec_files)):
        mf = open('lock/'+path_leaf(list_of_dec_files[i]), 'r')
        message = mf.read()
        mf.close()
        name = path_leaf(list_of_dec_files[i]).split('_')[1]
        #print "name:", name
        for j in range(len(list_of_tag_files)):
            if path_leaf(list_of_tag_files[j]).split('_')[1] == name:
                t = open('lock/'+path_leaf(list_of_tag_files[j]) , 'r')
                tag = t.read()
                t.close()
                validity = CBC_mac_verification(message, extract_mac_key, tag)
                #print validity
                #print "len of mess: " , len(message)
                #print "len of unhex mes: " , len(message)
                if validity == 'valid tag':
                    print list_of_tag_files[j]," is  valid"
                    iv = open('lock/IVs.txt', 'r')
                    IVs = iv.read()
                    iv.close()
                    #print "iv len: ", len(IVs.split(';')[i])
                    #print "encrypted message len: ", len(build_message_blocks(message, block_length))
                    decrypted_file = CBC_decryption(build_message_blocks(message, block_length), extract_sym_key, IVs.split(';')[i])
                    mf = open('lock/'+path_leaf(list_of_dec_files[i]), 'w')
                    print list_of_dec_files[i] , " is decrypted"

                    decrypted_and_pad_removed = [x.rstrip('\0') for x in decrypted_file]

                    mf.write(''.join(decrypted_and_pad_removed))
                    #print "decryption has written in the file"
                    mf.close()
                    #print decrypted_file

                else:
                    print "This MAC is invalid and you can not decrypt the file"
                    break

    # Delete auxiliary files
    del_auxiliary_files()
    return

def unlock_directory(path):
    global locker_N, locker_pk, locker_sk, unlocker_sk, unlocker_pk, unlocker_N, key2

    sym_keys_file = open(path , 'r')
    cert_data = sym_keys_file.read() 
    sym_keys_file.close()

    rsa_dec_using_loker_pk1 = RSA_decryption_supp_blocks(cert_data.split(';')[0] , int((cert_data.split(';')[4])[2:],16) , num_bits, locker_N , locker_pk)
    rsa_dec_using_loker_pk2 = RSA_decryption_supp_blocks(cert_data.split(';')[1] , int((cert_data.split(';')[5])[2:],16) , num_bits, locker_N , locker_pk)
    
    rsa_dec_using_unloker_sk1 = RSA_decryption_supp_blocks(rsa_dec_using_loker_pk1 , int((cert_data.split(';')[2])[2:],16) , num_bits, unlocker_N, unlocker_sk)
    rsa_dec_using_unloker_sk2 = RSA_decryption_supp_blocks(rsa_dec_using_loker_pk2 , int((cert_data.split(';')[3])[2:],16) , num_bits, unlocker_N, unlocker_sk)

    file_name = 'lock/symmetric_keys.txt'
    sym_key = open(file_name, 'w')

    sym_key.write(binascii.unhexlify(rsa_dec_using_unloker_sk1))
    sym_key.write(';')
    sym_key.write(binascii.unhexlify(rsa_dec_using_unloker_sk2))
    sym_key.close()
    #print rsa_dec_using_unloker_sk1 
    #print rsa_dec_using_unloker_sk2 
    k = open(file_name, 'r')
    ke = k.read()
    key2 = ke
    k.close()
    return file_name, "lock/*.txt"

def generate_cert():
    rsa_enc_using_id1, num_blocks1 = RSA_encryption_supp_blocks(hex(people[1]["public_key"])[2:-1], num_bits, people[2]["order"],  people[2]["private_key"])
    #print "rsa_enc_using_id1: " , rsa_enc_using_id1
    #print num_blocks1
    rsa_enc_using_id2, num_blocks2 = RSA_encryption_supp_blocks(rsa_enc_using_id1, num_bits, people[3]["order"],  people[3]["private_key"])
    #print "rsa_enc_using_id2: " , rsa_enc_using_id2 , num_blocks2
    self_sign, num_blocks3 =  RSA_encryption_supp_blocks(rsa_enc_using_id2, num_bits, people[1]["order"],  people[1]["private_key"])
    #print "self_sign:" , self_sign , num_blocks3

    cert_file = open('certificate.txt' , 'w')
    cert_file.write(self_sign)
    cert_file.write(';')
    cert_file.write(hex(num_blocks1))
    cert_file.write(';')
    cert_file.write(hex(num_blocks2))
    cert_file.write(';')
    cert_file.write(hex(num_blocks3))
    cert_file.close()

def verify_cert(public_key,id1, cert_file_name):

    cert_file = open(cert_file_name , 'r')
    cert_data = cert_file.read() 
    cert_file.close()
    #print "cert_data:" ,cert_data.split(';')[0]
    rsa_dec_using_self = RSA_decryption_supp_blocks(cert_data.split(';')[0] , int((cert_data.split(';')[3])[2:],16) , num_bits, people[1]["order"], people[1]["public_key"])
    rsa_dec_using_id2 = RSA_decryption_supp_blocks(rsa_dec_using_self, int((cert_data.split(';')[2])[2:],16) , num_bits, people[3]["order"], people[3]["public_key"])
    rsa_dec_using_id1 = RSA_decryption_supp_blocks(rsa_dec_using_id2 , int((cert_data.split(';')[1])[2:],16) , num_bits,people[2]["order"], people[2]["public_key"])
    
    print "rsa_dec_using_id1:" , int(rsa_dec_using_id1, 16)
    print "public key :" ,public_key
    print "pub_key hex: ", hex(public_key)
    if int(rsa_dec_using_id1, 16) == public_key:
        print "your certificate is valid"
    else:
        print "your certificate is invalid"


if __name__=='__main__':
    
    # Problem 1:
    print "Wait for a second, the key is generated first..."
    p,q = generate_p_q(num_bits)
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

    print "\nLocking a directory"
    path = 'lock/*.txt'
    print "The default path of the directory is 'lock/*.txt'"
    
    #inp = raw_input("Enter the direcrectory (please name the files in the directory as file_i.txt): ")
    #path = inp

    inp = raw_input('Enter the name of the locker: ')
    print "Generating sk and pk for ", inp,"..."
    p , q = generate_p_q(num_bits)
    locker_key_generator(p , q , inp)
    print "A public key and a private key have been assigned to ", inp

    inp0 = raw_input('Enter the name of the unlocker: ')
    print "Generating sk and pk for the unlocker..."
    p , q = generate_p_q(num_bits)
    unlocker_key_generator(p , q , inp0)
    print "these private and  public keys have been generated for you: "
    print "private key:", unlocker_sk
    print "public key:", unlocker_pk
    '''
    inp1 = raw_input('Enter the name of CA1: ')
    p , q = generate_p_q(num_bits)
    assigning_keys(p , q , inp1)
    inp2 = raw_input('Enter the name of the CA2: ')
    p , q = generate_p_q(num_bits)
    assigning_keys(p , q , inp2)
    #generate_cert()
    #verify_cert(unlocker_pk, inp0, 'certificate.txt')
    '''
    #print people
    fname = lock_directory(path)
    pk = raw_input("Enter your public key in order to unlock {}: ".format(path))
    #print type(pk)
    if int(pk) == unlocker_pk:
        name, files = unlock_directory(fname)
        mac_verification(name, files)
    else:
        print "your public key is not valid"
        del_auxiliary_files()
       



