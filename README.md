# CBC, CTR, CBC_Mac, Hash_and_Mac and RSA implementatio
## CBC and CTR
In this code we use exampleInputA.txt as the input plain text and exampleKeyOnes.txt as the key for CBC and CTR mode ciphers and CBC mac and Hash and mac. The results from each function are saved in a file. Here are the file names and their content:

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

## MAC
We use the same inputs(plain text and key) as the previous section to generate CBC mac and Hash and mac. The reasults are saved in CBC_mac.txt and hash_mac.txt. Files 'tag.txt' and 'message.txt' are provided in order to verify a massage and a tag. You can edit these files and use your own input in hex.

## RSA
In this section we also use exampleInputA.txt file as the input. The results are saved in files as follows.

content | file name | 
--- | --- |
Public key |p_key.txt |
Private keys |s_key.txt |
RSA encryption |rsa_encryption.txt|
RSA decryption |rsa_decryption.txt|

### How to run the program
...
pyhon programming_assignment_2.py
...
