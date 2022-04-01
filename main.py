from Crypto.Cipher import AES
import sys
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad



def writeStringToFile(string, outputFile):
    file = open(outputFile, "w")
    file.write(string)
    file.close()


def writeBytesToFile(string, outputFile):
    file = open(outputFile, "wb")
    file.write(string)
    file.close()


def readFileString(file):
    try:
        with open(file) as f:
            line = f.read()
            line = line.lower()
            return line

    except FileNotFoundError:
        print("Could not open file string", file)


def readFileBytes(file):
    try:
        with open(file, "rb") as f:
            line = f.read()
            line = line.lower()
            return line

    except FileNotFoundError:
        print("Could not open file bytes", file)


def encrypt(plainTextFile, keyFile, cipherTextFile):
    plaintext = readFileBytes(plainTextFile)            # read plaintext as binary
    key = readFileBytes(keyFile)                        # read keyFile to get key
    if len(plaintext) % 16 != 0:
        plaintext = pad(plaintext, 16)
    cipher = AES.new(key, AES.MODE_ECB)                 # create cipher with key
    cipherText = cipher.encrypt(plaintext)              # encrypt plaintext and get cipher text
    print("Cipher Text = ", cipherText)
    writeBytesToFile(cipherText, cipherTextFile)        # write ciphertext to cipherTextFile


def decrypt(cipherTextFile, keyFile, plainTextFile):
    ciphertext = readFileBytes(cipherTextFile)
    key = readFileBytes(keyFile)
    cipher = AES.new(key, AES.MODE_ECB)
    plainText = cipher.decrypt(ciphertext)
    print(plainText.decode())                           #decode returns string type... also it doesn't work
    #plainText = unpad(plainText, 16)                   #I wasn't able to get this working
    print(plainText)
    writeStringToFile(plainText, plainTextFile)



def generateKey(keySize, keyFile):
    keySize = int(keySize)/8                           #The user enters the keysize which for AES is 128, 196, or 256. Since we're working with bytes divide that number by 8
    keySize = int(keySize)
    key = get_random_bytes(keySize)
    print("Key = ", key)
    writeBytesToFile(key, keyFile)


if __name__ == '__main__':
    if sys.argv[1] == '-e':
        # arg 2 is the file containing the plain text/the text to be encrypted
        # arg 3 is the file containing the key that was generated
        # arg 4 is the file the encrypted text will be stored in
        #
        try:
            encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
        except ValueError as e:
            print("Illegal entry attempting to encrypt:", e)

    elif sys.argv[1] == '-d':
        # arg 2 is the file containing the text to be decrypted/the cipher text
        # arg 3 is the file containing the key that was generated
        # arg 4 is the file the decrypted text will be stored in
        #
        try:
            decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
        except ValueError as e:
            print("Illegal entry attempting to decrypt:", e)
        except TypeError as e:
            print("Illegal entry attempting to decrypt:", e)

    elif sys.argv[1] == '-g':
        ####need to check for valid key sizes: 128, 196, 256
        # arg 2 is the keysize
        # arg 3 is the file the key is stores in
        #
        try:
            generateKey(sys.argv[2], sys.argv[3])

        except ValueError:
            print("Illegal entry when attempting to generate key")

    else:
        print("Incorrect entry")