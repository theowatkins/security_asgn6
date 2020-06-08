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
        self.name = name # A string to identify yourself to others
        # All dictionaries below have keys of another user tied to 
        #   communication data for that user
        self.pgPairs = {} # A dictionary to hold p-g pairs
        self.shared = {} # A dictionary of shared keys
        self.private = {} # your randomly selected private value
        self.public = {} # your calculated public value
    
    # Generate a p-g pair and send it out with your name
    # and is establishing connection with other
    # If a connection was previously established with other, it is overwritten
    def initiateContact(self, other: str, pgVals: (int, int) = None):
        if (pgVals is None):
            elGam: ElGamal.ElGamalKey = ElGamal.generate(256, RandBytes) # Would be larger p in practice
            p: int = int(elGam.p)
            g: int = int(elGam.g)
        else:
            p = pgVals[0]
            g = pgVals[1]
        self.pgPairs[other] = (p, g)
        self.private[other] = random.randrange(p)
        self.public[other] = pow(g, self.private[other], p)
        return ((p, g), self.name, other)

    # Receive a contact initiation from a sender
    # Initilize communication values
    # If a connection was previously established with sender, it is overwritten
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

    # Simlulate a malicous actor intercepting a contact initiation
    # Attempts in vain to establish  valid connections with both the 
    #   sender and receiver to eavesdrop on messages between the two
    def maliciousReceiver(self, contactInfo):
        p = contactInfo[0][0]
        g = contactInfo[0][1]
        sender = contactInfo[1]
        intendedTarget = contactInfo[2]
        self.pgPairs[sender] = contactInfo[0]
        self.private[sender] = random.randrange(p) # This is why eavesdropping is pointless
        self.public[sender] = pow(g, self.private[sender], p)
        self.pgPairs[intendedTarget] = contactInfo[0]
        self.private[intendedTarget] = random.randrange(p)  # This is why eavesdropping is pointless
        self.public[intendedTarget] = pow(g, self.private[sender], p)

    # Send out your own name and public value to other
    def sendPub(self, other):
        return (self.name, self.public[other])

    # Accept a public value from other, compute the shared key
    def computeShared(self, senderPublic: (str, int)):
        sender = senderPublic[0]
        s = pow(senderPublic[1], self.private[sender], self.pgPairs[sender][0])
        self.shared[sender] = SHA256.new(intToBytes(s)).digest()

    # Send a message to the designated receiver by encrypting it with the shared key
    def sendMessage(self, receiver: str, message: str):
        # Uee firt 16 bytes of shared key as key for AES, use last 16 as the IV (?)
        aesBlock = AES.new((self.shared[receiver])[:16], AES.MODE_CBC, (self.shared[receiver])[-16:]) 
        return (aesBlock.encrypt(padTo16(bytes(message, "utf8"))), self.name)

    # Recieve a message by decrypting it using the key shared with the user that sent it
    def receiveMessage(self, incoming: (bytes, str)):
        try:
            # Uee firt 16 bytes of shared key as key for AES, use last 16 as the IV (?)
            aesBlock = AES.new((self.shared[incoming[1]])[:16], AES.MODE_CBC, (self.shared[incoming[1]])[-16:])
            try:
                return(trimPad(aesBlock.decrypt(incoming[0])).decode("utf8"))
            except:
                return("<Indecipherable Garbage>")
        except:
            return("No connection established with the user who sent this message")

    def __repr__ (self):
        return ("Name: " + self.name +
                "\npgVals w/: " + str(self.pgPairs.keys()) + 
                "\nprivate w/: " + str(self.private.keys()) + 
                "\npublic w/: " + str(self.public.keys()) + 
                "\nshared w/: " + str(self.shared.keys()))

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

def nl(f):
    f.write("\n")

# Run a simple Diffie-Helman Key Exchange example scenario
def simpleDiffieHelman():
    # Initialize users Alice, Bob, and Eve
    # Eve is going to try and steal their messages by intercepting all public comms (but no MITM) 
    alice = User("Alice")
    bob = User("Bob")
    eve = User("Eve")

    testP = int("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16)
    testG = int("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16)

    # Alice wants to start a conversation with Bob
    convoPG = alice.initiateContact("Bob", (testP, testG))
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

    out = open("DH_Example.txt", "w")

    # Alice and Bob start talking in secret
    out.write("\nAlice and Bob's conversation:\n")
    m1 = alice.sendMessage("Bob", "Hello Bob!")
    m2 = bob.sendMessage("Alice", "Hey Alice, what's up?")
    m3 = alice.sendMessage("Bob", "Let's plan a suprise for Eve")
    out.write(bob.receiveMessage(m1))
    nl(out)
    out.write(alice.receiveMessage(m2))
    nl(out)
    out.write(bob.receiveMessage(m3))
    nl(out)
    out.write("\nWhat Eve sees:\n")
    out.write(eve.receiveMessage(m1))
    nl(out)
    out.write(eve.receiveMessage(m2))
    nl(out)
    out.write(eve.receiveMessage(m3))
    nl(out)

    out.write("\nNow Bob wants to talk to Eve")

    newConvo = bob.initiateContact("Eve")
    eve.receiveContact(newConvo)
    evePub = eve.sendPub("Bob")
    bobPub = bob.sendPub("Eve")
    eve.computeShared(bobPub)
    bob.computeShared(evePub)

    out.write("\nBob and Eve's conversation:\n")
    out.write(eve.receiveMessage(bob.sendMessage("Eve", "Hello Eve!")))
    nl(out)
    out.write(bob.receiveMessage(eve.sendMessage("Bob", "Hey Bob, what's up?")))
    nl(out)
    out.write(eve.receiveMessage(bob.sendMessage("Eve", "Want to come over later?")))
    nl(out)

    out.write("\nAnd Bob and Alice can still talk:\n")
    out.write(alice.receiveMessage(bob.sendMessage("Alice", "Hey Alice, I got Eve to come over later, she doesn't suspect anything")))
    nl(out)
    out.write(bob.receiveMessage(alice.sendMessage("Bob", "Cool!")))

    out.close()

def main(argv):
    simpleDiffieHelman()

if __name__ == "__main__":
    main(sys.argv)