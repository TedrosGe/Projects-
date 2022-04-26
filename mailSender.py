from inspect import signature
import socket                   # Import socket module
from partialSecretExchange import PartialSecretExchangeA
from keyGeneration import DESkeyGenerationA, convertToBinary, convertToBytes
from EncryptClasses import EncryptDES, EncryptRSA
from Crypto.PublicKey import RSA
import os
from declaration import certifiedMailDeclaration
from random import randint
from time import sleep
from hashlib import sha512

s = socket.socket()             # Create a socket object
port = 60001                    # Reserve a port for your service.

s.connect(('127.0.0.1', port))

#s.send("Hello mailReceiver".encode("utf-8"))

mail = input("Write the mail to send to B: ")

# Testing Key Generation
N = 4 # Number of pairs of keys

key0, keys1, keys2 = DESkeyGenerationA(N)
print("Generated Keys:")
print(key0)
print(keys1)
print(keys2)
print("")

# Format used for PSE
keys1Bin, keys2Bin = convertToBinary(keys1, keys2, N)
key0Bin = '0b' + bin(key0)[2:].zfill(64)
print("Generated Keys in Binary:")
print(key0Bin)
print(keys1Bin)
print(keys2Bin)
print("")

# Format used for DES
keys1Bytes, keys2Bytes = convertToBytes(keys1, keys2, N)
key0Bytes = key0.to_bytes(8, byteorder='big')
print("Generated Keys in Bytes:")
print(key0Bytes)
print(keys1Bytes)
print(keys2Bytes)
print("")

# Bogus message
bogus = "This is a bogus message"
# Compute all C values (DES) (One of the is the mail above encrypted)
encryptDES = EncryptDES()
c = encryptDES.encrypt(mail, key0Bytes)

ca_0_to_3 = []
ca_4_to_7 = []

for i in range(0, N):
    zero_to_3 = encryptDES.encrypt(bogus, keys1Bytes[i])
    four_to_7 = encryptDES.encrypt(bogus, keys2Bytes[i])
    ca_0_to_3.append(zero_to_3)
    ca_4_to_7.append(four_to_7)

#print all c values
print("ca0:",c)
print("")
print("ca1 to can:",ca_0_to_3)
print("")
print("ca(n+1) to ca2n:",ca_4_to_7)
print("")

# Transmit all C values
s.send(c)

for i in range(0,N):
    s.send(ca_0_to_3[i])
    sleep(0.1)

for i in range(0,N):
    s.send(ca_4_to_7[i])
    sleep(0.1)

# Receive signed declaration
signatureRecv = s.recv(1024)
n = s.recv(1024)
e = s.recv(1024)

sigD= signatureRecv.decode()
sigint=int(sigD)

nstr=n.decode()
nint=int(nstr)

estr=e.decode()
eint=int(estr)

# Verify signature on declaration (RSA)
declaration = certifiedMailDeclaration()

hash = int.from_bytes(sha512(declaration).digest(), byteorder='big')
hashFromSignature = pow(sigint, eint, nint)
if hash == hashFromSignature:
    print("Signature valid:", hash == hashFromSignature)
else:
    print("Signature invalid")

# Testing PSE
secrets0RecvInt, secrets1RecvInt = PartialSecretExchangeA(keys1Bin, keys2Bin, s, N, 64)
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
secrets0RecvBin, secrets1RecvBin = convertToBytes(secrets0RecvInt, secrets1RecvInt, N)
print("Received Secrets in Bytes:")
print(secrets0RecvBin)
print(secrets1RecvBin)
print("")


#####################

# Testing PSE with CHEATING
secrets0 = ['0b0001100', '0b0100010']
secrets1 = ['0b0111000', '0b1001110']
PartialSecretExchangeA(secrets0, secrets1, s, 2, 7)

s.close()