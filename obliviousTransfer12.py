
from Crypto.PublicKey import RSA
import random
import base64

# The sender should run this function
# Secret0 and Secret 1 should be binary numbers. Eg. :
# Secret0 = 0b10000111, Secret1 = 0b10100100
def obliviousTransfer12A(secret0, secret1, sock):
    
    # Generate RSA public and private key
    rsaKey = RSA.generate(1024)
    
    # Send the public key
    rsaKeyPublic = rsaKey.publickey()
    rsaKeyPublicPEM = rsaKeyPublic.exportKey('PEM')
    #print(rsaKeyPublicPEM)
    sock.send(rsaKeyPublicPEM)
    
    # Generate and send 2 random messages (X0, X1)
    X0 = int(random.choice(range(0,10000000)))
    X1 = int(random.choice(range(0,10000000)))
    delimiter = ", "
    msg = str(X0) + delimiter + str(X1)
    msg = msg.encode("utf-8")
    sock.send(msg)
    
    # Receive v
    vRecv = sock.recv(1024)
    v = base64.b64decode(vRecv)
    v = int(v)
    
    # Calculate possible k values
    kEnc0 = v - X0
    kEnc1 = v - X1
    
    k0 = rsaKey.decrypt(kEnc0)
    k1 = rsaKey.decrypt(kEnc1)
    
    # Send both messages with the possible k values added to them
    m0 = secret0 + k0
    m1 = secret1 + k1
    mCombined = str(m0) + delimiter + str(m1)
    mCombined = mCombined.encode("utf-8")
    sock.send(mCombined)
    

# The recipient should run this function
def obliviousTransfer12B(sock):
    
    # Receive the public key
    msg = sock.recv(1024)
    #print("Message Received: ")
    #print(msg)
    rsaKeyPublic = RSA.importKey(msg)
    #print("Public Key: ")
    #print(rsaKeyPublic)
    
    # Receive 2 random messages (X0, X1)
    msgRecv = sock.recv(1024)
    msg = msgRecv.decode("utf-8")
    delimiter = ", "
    msgSplit = msg.split(delimiter)
    X0 = int(msgSplit[0])
    X1 = int(msgSplit[1])
    
    # Choose b (either 0 or 1) and generate a random number k
    bOptions = [0, 1]
    b = random.choice(bOptions) # For now, choose b randomly
    k = int(random.choice(range(0,100000)))
    
    # Encrypt k and blind it with Xb
    kEnc, = rsaKeyPublic.encrypt(k, int(random.choice(range(0,100000))))
    if b == 0:
        X = X0
    else: # b = 1
        X = X1
    v = kEnc + X
    
    # Encode v for sending over socket
    encodedV = base64.b64encode(str(v).encode())
    
    # Send v
    sock.send(encodedV)
    
    # Receive the 2 secrets (it can only decrypt one of them)
    msgRecv = sock.recv(1024)
    mCombined = msgRecv.decode("utf-8")
    mSplit = mCombined.split(delimiter)
    m0 = int(mSplit[0])
    m1 = int(mSplit[1])
    
    m0Decrypted = m0 - k
    m1Decrypted = m1 - k
    if b == 0:
        m = m0Decrypted
    else: # b = 1
        m = m1Decrypted
    
    return m