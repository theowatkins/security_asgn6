# Harrison DeWitt & Theo Watkins
# CPE 321, DeBruhl
# Assignment 6

import sys
from Cryptodome.Util import number as UtilNum
from Cryptodome.PublicKey import ElGamal
from Cryptodome.Random import get_random_bytes as RandBytes
from Cryptodome.Random import random
from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES

class User:
    def __init__ (self, name: str, pgPair: (int, int) = None):
        if (pgPair is None):
            elGam: ElGamal.ElGamalKey = ElGamal.generate(256, RandBytes) # In practice would be much larger, but takes a long time to run
            self.p: int = int(elGam.p)
            self.g: int = int(elGam.g)
        else:
            self.p = pgPair[0]
            self.g = pgPair[1]
        self.name = name # A string to identify yourself to others
        self.shared = {} # A dictionary of shared keys. The {key:value} pairs are {name:key shared with that user}
        self.private = random.randrange(self.p) # your randomly selected p value (In theory would be differnet for each connection with another user)
        self.public = pow(self.g, self.private, self.p) # your randomly selected g value (In theory would be differnet for each connection with another user) 
    
    # Send out your own p & g pair. Assumed to be used when self generated p and g, 
    # and is establishing connection with other
    def sendPG(self):
        return (self.p, self.g)

    # Send out your own name and public key
    def sendPub(self):
        return (self.name, self.public)

    # Accept a public key from other, compute the shared key
    def compShared(self, otherPub: (str, int)):
        s= pow(otherPub[1], self.private, self.p)
        self.shared[otherPub[0]] = SHA256.new(intToBytes(s)).digest()[:16]

    # Send a message to the designated receiver by encrypting it with the shared key
    def sendMessage(self, receiver: str, message: str):
        aesBlock = AES.new(self.shared[receiver], AES.MODE_ECB)     # How to do this with CBC?
        return (aesBlock.encrypt(padTo16(bytes(message, "utf8"))), self.name)

    # Recieve a message by decrypting it using the key shared with the user that sent it
    def receiveMessage(self, incoming: (bytes, str)):
        try:
            aesBlock = AES.new(self.shared[incoming[1]], AES.MODE_ECB)  # How to do this with CBC?
            print(trimPad(aesBlock.decrypt(incoming[0])))
        except:
            print("No connection established with the user who sent this message")

    def __repr__ (self):
        return ("Name: " + self.name +
                "\np: " + str(self.p) + 
                "\ng: " + str(self.g) + 
                "\nprivate: " + str(self.private) + 
                "\npublic: " + str(self.public) + 
                "\nshared: " + str(self.shared))

# convert an integer to a string of bits representing the equivalent binary
def intToBits(i):
    retStr = (bin(i)[2:])
    return (retStr)

# generates a bytearray from a string of bits
def bitsToBytes(bitStr):
    retBytes = bytearray()
    for i in range(0, len(bitStr), 8):
        retBytes.append(int(bitStr[i:i+8], 2))
    return retBytes

# Convert an integer to a bytearray object for the sake of encryption with AES
def intToBytes(num: int):
    return bitsToBytes(intToBits(num))

# generates a pad of n bytes following PKCS#7 padding
def makePad(n):
     padStr = ""
     i = 0
     while i < n:
          padStr += chr(n)
          i += 1
     pad = bytes(padStr, "utf8")
     return pad

# pads a message length to be divisible by 16
def padTo16(message):
     ret = message
     padSize = 16 % len(ret)
     pad = makePad(padSize)
     ret += pad
     return ret

# Identify and trim any padding from a plaintext message
def trimPad(message):
     end = message[-1]
     if (end < 16 and makePad(end) == message[(len(message) - end):]):
          return message[:(len(message) - end)]
     else:
          return message

# Run a simple Diffie-Helman Key Exchange example scenario
def simpleDiffieHelman():
    # Initialize two users, Alice and Bob
    alice = User("Alice", (37, 5))  # remove second argument to generate own p and g
    bob = User("Bob", alice.sendPG())

    # Alice sends public key to Bob, Bob computes the shared key
    bob.compShared(alice.sendPub())
    # Bob sends public key to Alice, Alice computes the shared key
    alice.compShared(bob.sendPub())

    # Alice sends a secret message to Bob, Bob receives and decrypts it
    bob.receiveMessage(alice.sendMessage("Bob", "Hello Bob!"))

def main(argv):
    simpleDiffieHelman()

if __name__ == "__main__":
    main(sys.argv)