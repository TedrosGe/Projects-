

from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class EncryptDES(object):
    
    def __init__(self, paddingChar="0"):
        
        self.paddingChar = paddingChar
    
    
    def append_space_padding(self, plaintext, blocksize=8):
        
        paddedText = plaintext + ""
        
        # Add padding until it becomes a multiple of the blocksize
        while((len(paddedText) % blocksize) != 0):
            paddedText = paddedText + self.paddingChar
            
        return paddedText
    
    
    def encrypt(self, plaintext, key):
        
        # Add padding to plaintext so that it is a multiple of blocksize (8) bytes
        Plaintext_pad = self.append_space_padding(plaintext)
        #print("Plaintext padded: " + str(Plaintext_pad))
        
        # Convert plaintext to bytes for DES (Encode)
        bytesOfPlaintext= Plaintext_pad.encode('UTF-8')
        #print("Plaintext padded in bytes: " + str(bytesOfPlaintext))
        
        # Encryption using DES library
        cipher = DES.new(key)
        ciphertext = cipher.encrypt(bytesOfPlaintext) # Convert to string?
        
        return ciphertext
        
    
    def remove_space_padding(self, paddedPlaintext, blocksize=8):
        
       plaintext = ""
       
       i = len(paddedPlaintext) - 1
       
       # Find out where the padding begins
       while(paddedPlaintext[i] == self.paddingChar):
           i -= 1
           
       # Truncate to the beginning of the padding
       plaintext = paddedPlaintext[0:(i+1)]
    
       return plaintext
    
    
    def decrypt(self, ciphertext, key):
        
        # Decryption using DES library
        cipher = DES.new(key)
        bytesOfPlaintext = cipher.decrypt(ciphertext)
        
        # Convert plaintext from bytes back to string
        Plaintext_pad = bytesOfPlaintext.decode('UTF-8')
        
        # Remove padding from plaintext
        plaintext = self.remove_space_padding(Plaintext_pad)
        
        return plaintext
    


class EncryptRSA(object):
    
    def __init__(self):
        
        super()
    
    
    def encrypt(self, plaintext, rsaKey):
        
        # Convert plaintext to bytes for RSA (Encode)
        bytesOfPlaintext= plaintext.encode('UTF-8')
        #print("Plaintext in bytes: " + str(bytesOfPlaintext))
        
        # Encryption using PKCS1_OAEP library
        cipher = PKCS1_OAEP.new(rsaKey)
        ciphertext = cipher.encrypt(bytesOfPlaintext)
        
        return ciphertext
    
    
    def decrypt(self, ciphertext, rsaKey):
        
        # Decryption using PKCS1_OAEP library
        cipher = PKCS1_OAEP.new(rsaKey)
        bytesOfPlaintext = cipher.decrypt(ciphertext)
        
        # Convert plaintext from bytes back to string
        plaintext = bytesOfPlaintext.decode('UTF-8')
        
        return plaintext