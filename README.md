# CBC, CTR, CBC_Mac, Hash_and_Mac and RSA implementatio
## CBC and CTR
In this code we use exampleInputA.txt as the input plain text for all the functions. We also use exampleKeyOnes.txt as the key for CBC and CTR mode ciphers and CBC mac and Hash and mac. The result from each function is saved in a file. File names used in this program are as followsff:

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
We use exampleInputA.txt as the message input for both CBC mac and Hash and mac. The reasult of them are saved in CBC_mac.txt and hash_mac.txt. Files 'tag.txt' and 'message.txt' are provided in order to verify a massage and a tag. You can edit these files and use your desierd input in hex.
## RSA
In this section we also use exampleInputA.txt file as the input. The result are saved in files as follows.
content | file name | 
--- | --- |
public and private keys |p_s_key.txt |
RSA encryption |rsa_encryption.txt|
RSA decryptio |rsa_decryption.txt|
CBC decryption |CBC_decryption.txt|
