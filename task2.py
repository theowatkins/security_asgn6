from task1 import *

# Run a Diffie-Helman Key Exchange example scenario with a MITM attack
def mitmDiffieHelman():
    # Initialize users Alice, Bob, and Mallory
    # Mallory is going to try and steal their messages with a MITM attack 
    alice = User("Alice")
    bob = User("Bob")
    mallory = User("Mallory")

    testP = int("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16)
    testG = int("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16)

    # Alice wants to start a conversation with Bob
    convoPG = alice.initiateContact("Bob", (testP, testG))
    # Bob receives the contact
    bob.receiveContact(convoPG)
    # Mallory intercepts the contact
    mallory.maliciousReceiver(convoPG)

    # Alice and Bob send out their public values
    # But they are intercepted and altered by the MITM (Mallory)
    alicePub = alice.sendPub("Bob")
    alicePub = ("Alice", convoPG[0][0])
    bobPub = bob.sendPub("Alice")
    bobPub = ("Bob", convoPG[0][0])

    # Alice and Bob each compute their shared key unaware that they
    # have received a corrupted public key from the other
    alice.computeShared(bobPub)
    bob.computeShared(alicePub)

    # Mallory computes a shared key with both Alice and Bob
    mallory.computeShared(alicePub)
    mallory.computeShared(bobPub)

    out = open("DH_Example.txt", "w")

    # Alice and Bob start talking in secret
    out.write("\nAlice and Bob's conversation:\n")
    m1 = alice.sendMessage("Bob", "Hello Bob!")
    m2 = bob.sendMessage("Alice", "Hey Alice, what's up?")
    m3 = alice.sendMessage("Bob", "Let's plan a suprise for Mallory")
    out.write(bob.receiveMessage(m1))
    nl(out)
    out.write(alice.receiveMessage(m2))
    nl(out)
    out.write(bob.receiveMessage(m3))
    nl(out)
    out.write("\nWhat Mallory sees:\n")
    out.write(mallory.receiveMessage(m1))
    nl(out)
    out.write(mallory.receiveMessage(m2))
    nl(out)
    out.write(mallory.receiveMessage(m3))
    nl(out)

    out.write("\nNow Bob wants to talk to Mallory")

    newConvo = bob.initiateContact("Mallory")
    mallory.receiveContact(newConvo)
    malloryPub = mallory.sendPub("Bob")
    bobPub = bob.sendPub("Mallory")
    mallory.computeShared(bobPub)
    bob.computeShared(malloryPub)

    out.write("\nBob and Mallory's conversation:\n")
    out.write(mallory.receiveMessage(bob.sendMessage("Mallory", "Hello Mallory!")))
    nl(out)
    out.write(bob.receiveMessage(mallory.sendMessage("Bob", "Hey Bob, what's up?")))
    nl(out)
    out.write(mallory.receiveMessage(bob.sendMessage("Mallory", "Want to come over later?")))
    nl(out)

    out.write("\nAnd Bob and Alice can still talk:\n")
    out.write(alice.receiveMessage(bob.sendMessage("Alice", "Hey Alice, I got Mallory to come over later, she doesn't suspect anything")))
    nl(out)
    out.write(bob.receiveMessage(alice.sendMessage("Bob", "Cool!")))

    out.close()

def main(argv):
    mitmDiffieHelman()

if __name__ == "__main__":
    main(sys.argv)