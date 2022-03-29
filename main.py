import sys

#************Methods below are just a sort of outline that I was thinking about
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
        with open(file) as f:
            line = f.read()
            line = line.lower()
            return line

    except FileNotFoundError:
        print("Could not open file")


def encrypt(plainText, keyFile, cipherText):
    print("This is where encryption will happen")
    print("plainText=", plainText)
    print("keyFile=", keyFile)
    print("cipherText=", cipherText)


def decrypt(cipherText, keyFile, plainText):
    print("This is where decryption will happen")
    print("cipherText=", cipherText)
    print("keyFile=", keyFile)
    print("plainText=", plainText)

def generateKey(keySize, keyFile):
    print("This is where the key will be generated")
    print("keySize=", keySize)
    print("keyFile=", keyFile)


if __name__ == '__main__':
    if sys.argv[1] == '-e':
        #arg 2 is the file containing the plain text/the text to be encrypted
        #arg 3 is the file containing the key that was generated
        #arg 4 is the file the encrypted text will be stored in
        #
        try:
            # key = int(sys.argv[3])
            # encryptedText = encrypt(sys.argv[2])
            # outputFile = sys.argv[4]
            # writeToFile(encryptedText, outputFile)
            encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
        except ValueError:
            print("Illegal entry")

    elif sys.argv[1] == '-d':
        # arg 2 is the file containing the text to be decrypted/the cipher text
        # arg 3 is the file containing the key that was generated
        # arg 4 is the file the decrypted text will be stored in
        #
        try:
            decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
        except ValueError:
            print("Illegal entry")

    elif sys.argv[1] == '-g':
        #arg 2 is the keysize
        #argument 3 is the file the key is stores in
        #
        try:
            generateKey(sys.argv[2], sys.argv[3])

        except ValueError:
            print("Illegal entry")

    else:
        print("Illegal entry")





