import base64
import json

from Crypto.Cipher import AES
import sys
from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# Must use key size of factors of 128 like 16,32,48,64 etc to generate key with

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
        print("Could not open file")


def readFileBytes(file):
    try:
        with open(file, "rb") as f:
            line = f.read()
            line = line.lower()
            return line

    except FileNotFoundError:
        print("Could not open file")


def writeJsonToFile(jsonString, file):
    try:
        with open(file, 'w') as f:
            f.write(jsonString)

    except FileNotFoundError:
        print("Error writing json")


def readFromJsonFile(file):
    with open(file) as f:
        encryptedString = json.load(f)
        return encryptedString


def encrypt(plainTextFile, keyFile, cipherTextFile):
    plaintext = readFileBytes(plainTextFile)  # read plaintext as binary
    key = readFileBytes(keyFile)  # read keyFile to get key
    cipher = AES.new(key, AES.MODE_CBC)  # create cipher with key
    cipherTextBytes = cipher.encrypt(pad(plaintext, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    cipherText = b64encode(cipherTextBytes).decode('utf-8')
    result = json.dumps({'iv': iv, 'cipherText': cipherText})
    writeJsonToFile(result, 'jsonCiphertext.json')


def decrypt(cipherTextFile, keyFile, plainTextFile):
    key = readFileBytes(keyFile)
    b64 = readFromJsonFile('jsonCiphertext.json')
    iv = b64decode(b64['iv'])
    cipherText = b64decode(b64['cipherText'])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plainText = unpad(cipher.decrypt(cipherText), AES.block_size)
    plainText = plainText.decode('utf-8', 'ignore')
    writeStringToFile(plainText, plainTextFile)
    print("The unencrypted message is: ", plainText)


def generateKey(keySize, keyFile):
    keySize = int(keySize)
    if keySize in (128,196,256):
        keySize = int(keySize)/8
        keySize = int(keySize)
        key = get_random_bytes(keySize)
        print(key)
        writeBytesToFile(key, keyFile)
    else:
        print("Invalid key size entry, AES key sizes: 128, 196, 256")





if __name__ == '__main__':
    if sys.argv[1] == '-e':
        # arg 2 is the file containing the plain text/the text to be encrypted
        # arg 3 is the file containing the key that was generated
        # arg 4 is the file the encrypted text will be stored in
        #
        try:
            encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
        except ValueError:
            print("Invalid entry")

    elif sys.argv[1] == '-d':
        # arg 2 is the file containing the text to be decrypted/the cipher text
        # arg 3 is the file containing the key that was generated
        # arg 4 is the file the decrypted text will be stored in
        #
        try:
            decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
        except ValueError:
            print("Illegal entry")
        except TypeError:
            print("Illegal entry")

    elif sys.argv[1] == '-g':
        # arg 2 is the keysize
        # argument 3 is the file the key is stores in


        try:
            generateKey(sys.argv[2], sys.argv[3])
        except ValueError:
            print("Illegal entry")
        except IndexError:
            print("Generating a key takes two arguments: key size and a file name to store the key")

    # except ValueError:
    # print("Illegal entry")

    else:
        print("Illegal entry")

    print("Goodbye")
