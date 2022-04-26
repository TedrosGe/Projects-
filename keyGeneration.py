
import os

# Generate N pairs of DES keys, all keys are of length 8 bytes (64 bits)
# Returns the keys as integers
# This function should be used by the mail sender
# y = int.from_bytes( x, 'big' ) ---> gets int from bytes
# y.to_bytes(8, byteorder='big') ---> gets back bytes from int
def DESkeyGenerationA(N):
    
    keys1 = []
    keys2 = []
    
    key0 = int.from_bytes( os.urandom(8), "big" )
    
    for i in range(N):
        
        key1 = int.from_bytes( os.urandom(8), "big" )
        key2 = key0 ^ key1
        
        keys1.append(key1)
        keys2.append(key2)
        
    return key0, keys1, keys2


# Generate N pairs of DES keys, all keys are of length 8 bytes (64 bits)
# Returns the keys as integers
# This function should be used by the mail receiver
# y = int.from_bytes( x, 'big' ) ---> gets int from bytes
# y.to_bytes(8, byteorder='big') ---> gets back bytes from int
def DESkeyGenerationB(N):
    
    keys1 = []
    keys2 = []
    
    for i in range(N):
        
        key1 = int.from_bytes( os.urandom(8), "big" )
        key2 = int.from_bytes( os.urandom(8), "big" )
        
        keys1.append(key1)
        keys2.append(key2)
        
    return keys1, keys2


# Convert keys from integers to binary
def convertToBinary(keys1, keys2, N):
    
    keys1Bin = []
    keys2Bin = []
    
    for i in range(N):
        
        keys1Bin.append('0b' + bin(keys1[i])[2:].zfill(64))
        keys2Bin.append('0b' + bin(keys2[i])[2:].zfill(64))
        
    return keys1Bin, keys2Bin


# Convert keys from integers to bytes
def convertToBytes(keys1, keys2, N):
    
    keys1Bytes = []
    keys2Bytes = []
    
    for i in range(N):
        
        keys1Bytes.append(keys1[i].to_bytes(8, byteorder='big'))
        keys2Bytes.append(keys2[i].to_bytes(8, byteorder='big'))
        
    return keys1Bytes, keys2Bytes