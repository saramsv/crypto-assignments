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
locker_N = 13578275947231812381801163768958481795154898225789831311853670856240875848196937588861348184637336876342343167873528131875639353480054444619909331129743349035996562870163372224634154359670695423643670965991902532535423001834042393632564840390515910053320558267271672558690702034307735436025790120011219390705762889135108749516782667938052678401494300638256792809573827546268721755281296821592025506872764523360091895355275840347631248283123800482967811332467791159799009869530577121924897673033098940036253954235179001987707363831556059215148316733381821337347191586740327155611062884277782467858708110499883368367253L
locker_pk = 2512974540884541163048883072381530930653102103452512249861506335700974591478861870637373424749139237102731776129591557686903859333272396089900847648135382156321015058170220507355803458404218045675907563367748542148029991434614450567536024574440803418144295324938708234847357348464147847307822461534820491503916332409970674245706581556345051177028736425110627677691224508336234136349428548901911197916621284763485907743858895061126457612791800659983447023894309047846288920168597006631162257969463737205890513505104061780162106507673746611539468956731963134935697415514953204445112979123832189443872852011032779366959L
locker_sk =  10629711934544707372316047001016350801761571592368863212129522739719920623864336453550226171731296694930625372499705667854349804803543738432890314010035890036215875084948087535381327811967578554436925140605099723234817475350858264987859438585745106662121599492134786920664971518967051843735058221166259857908343147501739295704874312588704361529881046091779416481335181130112084123129744354461419501145671873080496580862533979141156368872388377538521952229857030235972270685098647343722377323302584628949298750177104125501624106082867680940724233892124819483326264309290111554003379169925447164594068926733184851259359L

unlocker_N =17076059940400425683392128595188431860450009109039050190504543919454907984471312207224880331561755973433739728255996194240658566795336700014144842593697721926819921072322897168177130027962664359203427057007999352861584593574565171761484399279734852581306911737459948703627575348853076182113682886522096765218656375994058415364357259527566108599686912506321705418027014725202531955586946481852939487483798876266505313041312543529979080686270865659724851273059192701889982948842038459012511250009908985199386616186887130275870943459671860695908934289458204172436211429455589038222342378630376553976649975814275220606851L
unlocker_pk = 8889515970282884736877184677128807569300615648519571615260868905343893082100382048539786085274594791040529094023316888836326597527865102886011983561830904423516525174858593679823608353710419651745498722453321768762333478276322057629740434877567881791462180270317203573499625906041194524378598696674512209392941459197786234431155364052610909084962923567236476197519326736893113625849220276791144865844493094635655851987781971538709912838531081098701265430638407696710125622401472553441300908912431058183073123638087926487502845314287340744616128840848346871160942140804874653805462949392334069156984442912886781945835L
unlocker_sk = 11185418659220893807066954092071924810925618367835577723782247629439344866326218216169857368223604896802263253482990674399086127175220865057663718533236394031368450396617684536343624916470379335788963821648012141230276429957778531173747806629310082512275710050422305665607043310344900870872269455369997946473836424562768180463189062327480084989387609674121900830680063778709376663668945342481453789957794597386394074717566850907232681684175612808941731468117165655034930803818228165809904224193607779874032961191410456814697038734151725545790766001251319147239104023411472618668380932732785133194781343870193695286211L
    
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
        c = RSA_deleting_zeros(c_block[i * num_bits : (i+1) * num_bits])
        c = int(c, 16)
        m = RSA_decryption(c, N, e)
        m = hex(m)
        m_block.append(m[-1 - (num_bits/2-24)/8*2 : -1])
    m = ''.join(m_block)
    m = RSA_deleting_zeros(m)
    return m


def lock_directory(path):
    
    files = glob.glob(path)
    # iterate over the list getting each file 
    mac_key = random_symmetric_key_generator(16)
    sym_keys_file = open('lock/symmetric_keys.txt' , 'w')
    sym_keys_file.write(mac_key)
    sym_keys_file.write(';')
    sym_keys_file.write(key)
    sym_keys_file.close()

    '''
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
        '''
    #p, q = generate_p_q(num_bits)
    #print "locker data: " , locker_key_generator(p , q)
    #p, q = generate_p_q(num_bits)
    #print "unlocker data: " , unlocker_key_generator(p, q)
    locker_N = 13578275947231812381801163768958481795154898225789831311853670856240875848196937588861348184637336876342343167873528131875639353480054444619909331129743349035996562870163372224634154359670695423643670965991902532535423001834042393632564840390515910053320558267271672558690702034307735436025790120011219390705762889135108749516782667938052678401494300638256792809573827546268721755281296821592025506872764523360091895355275840347631248283123800482967811332467791159799009869530577121924897673033098940036253954235179001987707363831556059215148316733381821337347191586740327155611062884277782467858708110499883368367253L
    locker_pk = 2512974540884541163048883072381530930653102103452512249861506335700974591478861870637373424749139237102731776129591557686903859333272396089900847648135382156321015058170220507355803458404218045675907563367748542148029991434614450567536024574440803418144295324938708234847357348464147847307822461534820491503916332409970674245706581556345051177028736425110627677691224508336234136349428548901911197916621284763485907743858895061126457612791800659983447023894309047846288920168597006631162257969463737205890513505104061780162106507673746611539468956731963134935697415514953204445112979123832189443872852011032779366959L
    locker_sk =  10629711934544707372316047001016350801761571592368863212129522739719920623864336453550226171731296694930625372499705667854349804803543738432890314010035890036215875084948087535381327811967578554436925140605099723234817475350858264987859438585745106662121599492134786920664971518967051843735058221166259857908343147501739295704874312588704361529881046091779416481335181130112084123129744354461419501145671873080496580862533979141156368872388377538521952229857030235972270685098647343722377323302584628949298750177104125501624106082867680940724233892124819483326264309290111554003379169925447164594068926733184851259359L

    unlocker_N =17076059940400425683392128595188431860450009109039050190504543919454907984471312207224880331561755973433739728255996194240658566795336700014144842593697721926819921072322897168177130027962664359203427057007999352861584593574565171761484399279734852581306911737459948703627575348853076182113682886522096765218656375994058415364357259527566108599686912506321705418027014725202531955586946481852939487483798876266505313041312543529979080686270865659724851273059192701889982948842038459012511250009908985199386616186887130275870943459671860695908934289458204172436211429455589038222342378630376553976649975814275220606851L
    unlocker_pk = 8889515970282884736877184677128807569300615648519571615260868905343893082100382048539786085274594791040529094023316888836326597527865102886011983561830904423516525174858593679823608353710419651745498722453321768762333478276322057629740434877567881791462180270317203573499625906041194524378598696674512209392941459197786234431155364052610909084962923567236476197519326736893113625849220276791144865844493094635655851987781971538709912838531081098701265430638407696710125622401472553441300908912431058183073123638087926487502845314287340744616128840848346871160942140804874653805462949392334069156984442912886781945835L
    unlocker_sk = 11185418659220893807066954092071924810925618367835577723782247629439344866326218216169857368223604896802263253482990674399086127175220865057663718533236394031368450396617684536343624916470379335788963821648012141230276429957778531173747806629310082512275710050422305665607043310344900870872269455369997946473836424562768180463189062327480084989387609674121900830680063778709376663668945342481453789957794597386394074717566850907232681684175612808941731468117165655034930803818228165809904224193607779874032961191410456814697038734151725545790766001251319147239104023411472618668380932732785133194781343870193695286211L
    sym_keys_file = open('lock/symmetric_keys.txt' , 'r')
    keys = sym_keys_file.read()
    sym_keys_file.close()


    rsa_enc_using_unlocker_pk1, num_blocks11 = RSA_encryption_supp_blocks(binascii.hexlify(keys.split(';')[0]) , num_bits, unlocker_N, unlocker_pk) 
    rsa_enc_using_unlocker_pk2, num_blocks12 = RSA_encryption_supp_blocks(binascii.hexlify(keys.split(';')[1]) , num_bits, unlocker_N, unlocker_pk) 
        
    rsa_enc_using_locker_sk1, num_blocks21 = RSA_encryption_supp_blocks(rsa_enc_using_unlocker_pk1, num_bits, locker_N , locker_sk)
    rsa_enc_using_locker_sk2, num_blocks22 = RSA_encryption_supp_blocks(rsa_enc_using_unlocker_pk2, num_bits, locker_N , locker_sk)

   
    sym_keys_file = open('lock/symmetric_keys.txt' , 'w')
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
    sym_keys_file = open(path , 'r')
    cert_data = sym_keys_file.read() 
    sym_keys_file.close()

    rsa_dec_using_loker_pk1 = RSA_decryption_supp_blocks(cert_data.split(';')[0] , int((cert_data.split(';')[4])[2:],16) , num_bits, locker_N , locker_pk)
    rsa_dec_using_loker_pk2 = RSA_decryption_supp_blocks(cert_data.split(';')[1] , int((cert_data.split(';')[5])[2:],16) , num_bits, locker_N , locker_pk)
    
    rsa_dec_using_unloker_sk1 = RSA_decryption_supp_blocks(rsa_dec_using_loker_pk1 , int((cert_data.split(';')[2])[2:],16) , num_bits, unlocker_N, unlocker_sk)
    rsa_dec_using_unloker_sk2 = RSA_decryption_supp_blocks(rsa_dec_using_loker_pk2 , int((cert_data.split(';')[3])[2:],16) , num_bits, unlocker_N, unlocker_sk)
    
    print rsa_dec_using_unloker_sk1 
    print rsa_dec_using_unloker_sk2 
    return 

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
    unlock_directory('lock/symmetric_keys.txt')
