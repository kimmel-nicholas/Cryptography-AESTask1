Examine crypto libraries for your choice of programming language of  Python 3  or Java.  


Use the library of your choice to implement a program that will


Generate an AES key of given key size and store it in a key file.
Encrypt the content of a given file using the key given in a file
Decrypt the content of a given file using the key given in a file
Name your file group#_AES.  The program will run from command line:


Key generation-

python  group#_AES    -g    keysize    keyfile

java    group#_AES    -g      keysize    keyfile

If invalid argument or keysize, let the user know and quit (do not crash).


Encryption-

python  group#_AES    -e   plain.txt     keyfile  encrypted.txt

java    group#_AES    -e      plain.txt     keyfile   encrypted.txt

If invalid argument or key, let the user know and quit (do not crash).


Decryption-

python  group#_AES    -d   cipher.txt     keyfile  decrypted.txt

java    group#_AES      -d     cipher.txt     keyfile  decrypted.txt

If invalid argument or key, let the user know and quit (do not crash).


Test your program before you submit. In your submission include screenshots of:


1. Successful key generation
2. Invalid key size when generating a key
3. Invalid argument when generating a key
4. Successful encryption
5. Invalid argument when encrypting
6. File does not exist message without crashing when encrypting
7. Invalid key when encrypting
8. Successful decryption  
9. Invalid argument when decrypting
10. File does not exist message without crashing when decrypting
11. Invalid key when decrypting
12. A side-by-side screenshot of plain.txt and decrypted.txt