import socket                   # Import socket module
from partialSecretExchange import PartialSecretExchangeB, PartialSecretExchangeB_CHEATING
from keyGeneration import DESkeyGenerationB, convertToBinary, convertToBytes
from declaration import certifiedMailDeclaration
from EncryptClasses import EncryptDES, EncryptRSA
from Crypto.PublicKey import RSA
from random import randint
from hashlib import sha512



port = 60001                    # Reserve a port for your service.
s = socket.socket()             # Create a socket object
host = socket.gethostname()     # Get local machine name
print(host)
s.bind(('127.0.0.1', port))            # Bind to the port
s.listen(5)                     # Now wait for client connection.


while True:
    conn, addr = s.accept()     # Establish connection with client.

    print("")
    print(f"Connection from {addr} has been established")
    
    #msg = (conn.recv(1024)).decode("utf-8")
    #print("Message Received: " + msg)
    print("")
    
    # Testing Key Generation
    N = 4  # Number of pais of keys

    keys1, keys2 = DESkeyGenerationB(N)
    print("Generated Keys:")
    print(keys1)
    print(keys2)
    print("")
    
    # Format used for PSE
    keys1Bin, keys2Bin = convertToBinary(keys1, keys2, N)
    print("Generated Keys in Binary:")
    print(keys1Bin)
    print(keys2Bin)
    print("")
    
    # Format used for DES
    keys1Bytes, keys2Bytes = convertToBytes(keys1, keys2, N)
    print("Generated Keys in Bytes:")
    print(keys1Bytes)
    print(keys2Bytes)
    print("")
    
    # Receive A's C values
    c = conn.recv(1024)
    ca_0_to_3 = [4]
    ca_4_to_7 = [4]
    
    for i in range(0,N):
        x = conn.recv(1024)
        ca_0_to_3.append(x)

    for i in range(0,N):
        y = conn.recv(1024)
        ca_4_to_7.append(y)

    print("c:",c)
    print("")
    print("ca1 to can", ca_0_to_3)
    print("")
    print("ca(n+1) to ca2n", ca_4_to_7)
    print("")
    
    # Compute all B's C values (DES) -> Apparently not used in the algorithm
    # Bogus message
    bogus = "This is a bogus message"
    encryptDES = EncryptDES()

    cb_0_to_3 = []
    cb_4_to_7 = []

    for i in range(0, N):
        zero_to_3 = encryptDES.encrypt(bogus, keys1Bytes[i])
        four_to_7 = encryptDES.encrypt(bogus, keys2Bytes[i])
        cb_0_to_3.append(zero_to_3)
        cb_4_to_7.append(four_to_7)
    
    # Declaration
    declaration = certifiedMailDeclaration()
    print("B's Declaration:")
    print(declaration)
    
    # Sign declaration (RSA)
    keyPair = RSA.generate(bits=1024)
    print(f"Public key:  (n={hex(keyPair.n)}, e={hex(keyPair.e)})")
    print(f"Private key: (n={hex(keyPair.n)}, d={hex(keyPair.d)})")


    hash = int.from_bytes(sha512(declaration).digest(), byteorder='big')
    signature = pow(hash, keyPair.d, keyPair.n)
    print("Signature:", hex(signature))
    # Transmit declaration
    str_sig = str(signature)
    str_n = str(keyPair.n)
    str_e = str(keyPair.e)

    byte_sig = str_sig.encode()
    conn.send(byte_sig)
    byte_n = str_n.encode()
    conn.send(byte_n)
    byte_e = str_e.encode()
    conn.send(byte_e)
    
    # PSE
    secrets0RecvInt, secrets1RecvInt = PartialSecretExchangeB(keys1Bin, keys2Bin, conn, N, 64)
    print("")
    print("Received Secrets in Int:")
    print(secrets0RecvInt)
    print(secrets1RecvInt)
    print("")
    
    # Convert to received secrets binary
    secrets0RecvBin, secrets1RecvBin = convertToBinary(secrets0RecvInt, secrets1RecvInt, N)
    print("Received Secrets in Binary:")
    print(secrets0RecvBin)
    print(secrets1RecvBin)
    print("")
    
    # Convert received secrets to bytes
    secrets0RecvBytes, secrets1RecvBytes = convertToBytes(secrets0RecvInt, secrets1RecvInt, N)
    print("Received Secrets in Bytes:")
    print(secrets0RecvBin)
    print(secrets1RecvBin)
    print("")
    
    # Decrypt A's C0 value (mail) using the received secrets (a0) (DES)
    # Calculate secret0Recv
    secret0RecvInt = secrets0RecvInt[0] ^ secrets1RecvInt[0]
    secret0RecvBytes = secret0RecvInt.to_bytes(8, byteorder='big')
    print("Calculated Key0:")
    print(secret0RecvBytes)
    print("")

    mailDecrypted = encryptDES.decrypt(c, secret0RecvBytes)
    print("Decrypted Mail: ",mailDecrypted)
    
    
    ###########################
    
    # Testing PSE with CHEATING
    secrets0 = ['0b0001011', '0b0010110']
    secrets1 = ['0b0100001', '0b0101100']
    incorrectSecrets0 = ['0b0000011', '0b0010110'] # The first item is different
    incorrectSecrets1 = ['0b0100001', '0b0101110'] # The second item is different
    PartialSecretExchangeB_CHEATING(secrets0, secrets1, incorrectSecrets0, incorrectSecrets1, conn, 2, 7)
    
    conn.close()