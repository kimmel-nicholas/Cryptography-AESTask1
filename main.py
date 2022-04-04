from Crypto.Cipher import AES
import sys
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# I took out the original padding stuff which used the pad tool from
# Cryptodome. I decided just to pad it with periods because then we actually
# know what to expect from the padding..if that makes any sense.
#
# I still couldnt figure out how to make everything work with writing and
# reading from files. I tried a bunch of things. To try to figure it out I
# added a new method that you can try from the command line. I think by using this method
# I/we can figure out what needs to change to make it work. The method which I named testerMeth,
# generates a key, pads, encrypts, and decrypts successfully all within the method.
# This way we can see how exactly it works without dealing with files which will hopefully help.
#
# To use the method, you just type whatever you want to encrypt into the command line which
# you can see in the below example:
#
#     python main.py -t something
#
# Now that I think about it, I don't know how it works with spaces since it might see any
# following words as a new arguument but regardless it works



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
    # if len(plaintext) % 16 != 0:
    #     plaintext = pad(plaintext, 16)

    while len(plaintext) % 16 != 0:
        plaintext+=b'.'
        print(plaintext)
    cipher = AES.new(key, AES.MODE_ECB)                 # create cipher with key
    cipherText = cipher.encrypt(plaintext)              # encrypt plaintext and get cipher text
    print("Cipher Text = ", cipherText)
    writeBytesToFile(cipherText, cipherTextFile)        # write ciphertext to cipherTextFile


def decrypt(cipherTextFile, keyFile, plainTextFile):
    ciphertext = readFileBytes(cipherTextFile)
    key = readFileBytes(keyFile)
    cipher = AES.new(key, AES.MODE_ECB)
    plainText = cipher.decrypt(ciphertext)
    plainText = plainText.decode("utf-8")                          #decode returns string type... also it doesn't work
    writeStringToFile(plainText, plainTextFile)



def generateKey(keySize, keyFile):
    keySize = int(keySize)/8                           #The user enters the keysize which for AES is 128, 196, or 256. Since we're working with bytes divide that number by 8
    keySize = int(keySize)
    key = get_random_bytes(keySize)
    print("Key = ", key)
    print(type(key))
    writeBytesToFile(key, keyFile)

def testerMeth(plain):
    print("Plain: \t\t\t\t\t\t", plain)
    plain = bytes(plain.encode())
    print("Plain but encoded to utf8 and bytes type: \t", plain)
    while len(plain) % 16 != 0:
        plain+=b'.'
    key = get_random_bytes(16)
    print("Key: \t\t\t\t\t\t", key)
    cipher = AES.new(key, AES.MODE_ECB)
    cipherText = cipher.encrypt(plain)
    print("Cipher text: \t\t\t\t\t", cipherText)
    plainText = cipher.decrypt(cipherText)
    print("Plain text after decryption: \t\t\t", plainText)




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

    elif sys.argv[1] == '-t':
            testerMeth(sys.argv[2])

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

#remove current padding, try using bin file, convert to bytes but keep the same characters, changing string to bytes
