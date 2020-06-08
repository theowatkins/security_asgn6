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
    def __init__ (self, name: str):
        self.pgPairs = {} # A dictionary to hold p-g pairs for lines of communication
        self.name = name # A string to identify yourself to others
        self.shared = {} # A dictionary of shared keys. The {key:value} pairs are {name:key shared with that user}
        self.private = {} # random.randrange(self.p) # your randomly selected p value (In theory would be differnet for each connection with another user)
        self.public = {} #pow(self.g, self.private, self.p) # your randomly selected g value (In theory would be differnet for each connection with another user) 
    
    # Generate a p-g pair and send it out with your name
    # and is establishing connection with other
    def initiateContact(self, other: str, pgVals: (int, int) = None):
        if (pgVals is None):
            elGam: ElGamal.ElGamalKey = ElGamal.generate(256, RandBytes) # In practice would be much larger, but takes a long time to run
            p: int = int(elGam.p)
            g: int = int(elGam.g)
        else:
            p = pgVals[0]
            g = pgVals[1]
        self.pgPairs[other] = (p, g)
        self.private[other] = random.randrange(p)
        self.public[other] = pow(g, self.private[other], p)
        return ((p, g), self.name, other)

    def receiveContact(self, contactInfo):
        if (self.name == contactInfo[2]):
            p = contactInfo[0][0]
            g = contactInfo[0][1]
            sender = contactInfo[1]
            self.pgPairs[sender] = contactInfo[0]
            self.private[sender] = random.randrange(p)
            self.public[sender] = pow(g, self.private[sender], p)
        else:
            print("They aren't trying to talk to me, that's ok!")

    def maliciousReceiver(self, contactInfo):
        p = contactInfo[0][0]
        g = contactInfo[0][1]
        sender = contactInfo[1]
        intendedTarget = contactInfo[2]
        self.pgPairs[sender] = contactInfo[0]
        self.private[sender] = random.randrange(p) # This is why intercepting is pointless
        self.public[sender] = pow(g, self.private[sender], p)
        self.pgPairs[intendedTarget] = contactInfo[0]
        self.private[intendedTarget] = random.randrange(p)  # This is why intercepting is pointless
        self.public[intendedTarget] = pow(g, self.private[sender], p)

    # Send out your own name and public key to other
    def sendPub(self, other):
        return (self.name, self.public[other])

    # Accept a public key from other, compute the shared key
    def computeShared(self, senderPublic: (str, int)):
        sender = senderPublic[0]
        s = pow(senderPublic[1], self.private[sender], self.pgPairs[sender][0])
        self.shared[sender] = SHA256.new(intToBytes(s)).digest()

    # Send a message to the designated receiver by encrypting it with the shared key
    def sendMessage(self, receiver: str, message: str):
        aesBlock = AES.new((self.shared[receiver])[:16], AES.MODE_CBC, (self.shared[receiver])[-16:])     # Need a shared IV, just use last 16 of shared key I guess?
        return (aesBlock.encrypt(padTo16(bytes(message, "utf8"))), self.name)

    # Recieve a message by decrypting it using the key shared with the user that sent it
    def receiveMessage(self, incoming: (bytes, str)):
        try:
            aesBlock = AES.new((self.shared[incoming[1]])[:16], AES.MODE_CBC, (self.shared[incoming[1]])[-16:])  # See same issue in sendMessage
            try:
                print(trimPad(aesBlock.decrypt(incoming[0])).decode("utf8"))
            except:
                print("<Indecipherable Garbage>")
        except:
            print("No connection established with the user who sent this message")

    def __repr__ (self):
        return ("Name: " + self.name +
                "\npgVals: " + str(self.pgPairs) + 
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
    inLen = len(message)
    while (inLen > 16):
        inLen -= 16
    padSize = 16 - inLen
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
    # Initialize users Alice, Bob, and Eve
    # Eve is going to try and steal their messages by intercepting all public comms (but no MITM) 
    alice = User("Alice")
    bob = User("Bob")
    eve = User("Eve")

    # Alice wants to start a conversation with Bob
    convoPG = alice.initiateContact("Bob")
    # Bob receives the contact
    bob.receiveContact(convoPG)
    # Eve intercepts the contact
    eve.maliciousReceiver(convoPG)

    # Alice and Bob send out their public values
    alicePub = alice.sendPub("Bob")
    bobPub = bob.sendPub("Alice")

    # Alice and Bob each compute their shared key
    alice.computeShared(bobPub)
    bob.computeShared(alicePub)

    # Eve computes a shared key with both Alice and Bob
    #  Pointless, these won't match with their real shared key
    eve.computeShared(alicePub)
    eve.computeShared(bobPub)

    # Alice and Bob start talking in secret
    print("\nAlice and Bob's conversation:\n")
    bob.receiveMessage(alice.sendMessage("Bob", "Hello Bob!"))
    alice.receiveMessage(bob.sendMessage("Alice", "Hey Alice, what's up?"))
    bob.receiveMessage(alice.sendMessage("Bob", "Even though Eve can intercept our messages she can't read them because we shared a key with DH Key Exchange"))
    print("\nWhat Eve sees:\n")
    eve.receiveMessage(alice.sendMessage("Bob", "Hello Bob!"))
    eve.receiveMessage(bob.sendMessage("Alice", "Hey Alice, what's up?"))
    eve.receiveMessage(alice.sendMessage("Bob", "Even though Eve can intercept our messages she can't read them because we shared a key with DH Key Exchange"))
    # THe key lists of ALice, Bob, and Eve
    print("\n==========================\n")
    print(alice)
    print("\n==========================\n")
    print(bob)
    print("\n==========================\n")
    print(eve)
    print("\n==========================")


def main(argv):
    simpleDiffieHelman()

if __name__ == "__main__":
    main(sys.argv)