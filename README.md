# Programming assignment 3
## Problem 1
The public key and secret key is generated first, saved as 'p_key.txt' and 's_key.txt'.

The program can run in two modes: signing mode and verification mode;

Signing mode: data should be provided either in command line or from file 'datatosign.txt', they should be all in hex (omit the '\x' in front).

Verification mode: data to verify should be provided either in command line or from file 'rsa_signature.txt', it will show the verification result.

## Problem 2
The RSA key generation function 'RSA_key_generation' is modified as requested.  

## Problem 3
In this part of the program a directory is locked as follows:

All the files are encrypted using CBC mode. A tags is generated for each file using a random symmetric key. After decrypting the symmetric keys using the private key of the locking party and the private key of the unlocking party, the unlocking party would have the symmetric keys. He the verifys the tages and decrypts the files using the recoverd keys.
We also provided a function in order to have a chain of certificates but unfortunately we are not using it here.

## How to run our interactive code
`python programmingassignment3.py`

# Programming assignment 2
## CBC, CTR, CBC_Mac, Hash_and_Mac and RSA implementation
### CBC and CTR
We implemented this programming assignment in python. In this code we use exampleInputA.txt as the input plain text and exampleKeyOnes.txt as the key for CBC and CTR mode ciphers and CBC mac and Hash and mac. The results from each function are saved in a file. Here are the file names and their content:

content | file name | 
--- | --- |
key |exampleKeyOnes.txt |
plain text |exampleInputA.txt|
CBC encryption |CBC_eccryption.txt|
CBC decryption |CBC_decryption.txt|
CBC IV |CBC_iv.txt|
CTR encryption |CBC_encryption.txt|
CTR decryption |CBC_decryption.txt|
CTR IV |CTR_iv.txt|

### MAC
We use the same inputs(plain text and key) as the previous section to generate CBC mac and Hash and mac. The reasults are saved in CBC_mac.txt and hash_mac.txt. Files 'tag.txt' and 'message.txt' are provided in order to verify a massage and a tag. You can edit these files and use your own input in hex.

### RSA
In this section we also use exampleInputA.txt file as the input. The results are saved in files as follows.

content | file name | 
--- | --- |
Public key |p_key.txt |
Private keys |s_key.txt |
RSA encryption |rsa_encryption.txt|
RSA decryption |rsa_decryption.txt|

### How to run our code

```
python programming_assignment_2.py
```



