

from obliviousTransfer12 import obliviousTransfer12A, obliviousTransfer12B

# Send a single bit (bit # j) from each secret (A -> B)
# Secrets0 and Secrets1 should both be lists of size N where Secrets0[i] and
# Secrets1[i] are pairs, so that the total number of secrets is 2N
# Each element in secrets0 and secrets1 should be binary numbers of length L,
# Eg. Secrets0[0] = 0b10000111, Secrets1[0] = 0b10100100 for L = 8
def sendBit(secrets0, secrets1, sock, N, j):
    
    # For each secret in secrets 0
    for i in range(0, N):
        
        # Bit j of the secret (string)
        bitj = secrets0[i][2+j] # +2 because the format from bin is '0bxxxxx...'
        
        # Send the bit
        encodedBitj = bitj.encode('utf-8')
        sock.send(encodedBitj)
        
    # For each secret in secrets 1
    for i in range(0, N):
        
        # Bit j of the secret (string)
        bitj = secrets1[i][2+j] # +2 because the format from bin is '0bxxxxx...'
        
        # Send the bit
        encodedBitj = bitj.encode('utf-8')
        sock.send(encodedBitj)


# Receive a single bit (bit # j) from each secret (A -> B)
# Secrets0 and Secrets1 should both be lists of size N where Secrets0[i] and
# Secrets1[i] are pairs, so that the total number of secrets is 2N
# Each element in secrets0 and secrets1 should be binary numbers of length LESS
# THAN L because these are the received secrets (incomplete - only the bits
# received so far)
def receiveBit(secrets0, secrets1, expectedSecrets, sock, N, j):
    
    # For each secret in secret0
    for i in range(0, N):
        
        # Receive and decode the bit for the secret
        bitRecv = sock.recv(1)
        bitRecvDecoded = bitRecv.decode('utf-8')
        
        secrets0[i] = secrets0[i] + bitRecvDecoded
        
    # For each secret in secret1
    for i in range(0, N):
        
        # Receive and decode the bit for the secret
        bitRecv = sock.recv(1)
        bitRecvDecoded = bitRecv.decode('utf-8')
        
        secrets1[i] = secrets1[i] + bitRecvDecoded
    
    # Check that at least one secret in each pair matches the expected secret
    # If not, print a message to alert and stop
    for i in range(0, N):
        
        if secrets0[i][2:j+3] == expectedSecrets[i][2:j+3]:
            continue
        if secrets1[i][2:j+3] == expectedSecrets[i][2:j+3]:
            continue
        
        print("")
        print("Received bit does not match expected bit from OT1/2 !")
        print("Cheating detected at bit: " + str(j))
    
    # Return the updated secrets
    return secrets0, secrets1

# Either the sender or the receiver run this function
# Secrets0 and Secrets1 should both be lists of size N where Secrets0[i] and
# Secrets1[i] are pairs, so that the total number of secrets is 2N
# Each element in secrets0 and secrets1 should be binary numbers of length L,
# Eg. Secrets0[0] = 0b10000111, Secrets1[0] = 0b10100100 for L = 8
def PartialSecretExchangeA(secrets0, secrets1, sock, N, L):
    
    # Oblivious Transfer/Receive One Secret From Each Pair
    
    # The list of secrets received from the other side using Oblivious Transfer
    receivedSecretsOT = []
    
    for i in range(0, N):
        
        obliviousTransfer12A(int(secrets0[i], 2), int(secrets1[i], 2), sock)
        receivedSecret = obliviousTransfer12B(sock)
        receivedSecretsOT.append(receivedSecret)
    
    print("")
    print("Received Secrets using OT12:")
    print(receivedSecretsOT)
    
    # Convert the received secrets to binary
    receivedSecretOTBin = []
    for i in range(0, N):
        receivedSecretOTBin.append('0b' + bin(receivedSecretsOT[i])[2:].zfill(L))
    print(receivedSecretOTBin)
    
    # Transfer/Receive All Secrets Bit by Bit
    
    # Initialize the array of secrets (N pairs)
    secrets0Recv = ['0b' for x in range(N)]
    secrets1Recv = ['0b' for x in range(N)]
    
    # For each bit #
    for j in range(0, L):
        
        # Send and receive a bit for each secret
        sendBit(secrets0, secrets1, sock, N, j)
        secrets0Recv, secrets1Recv = receiveBit(secrets0Recv, secrets1Recv, receivedSecretOTBin, sock, N, j)
        
    
    print("")
    print("Received Secrets from bit by bit transfer:")
    print(secrets0Recv)
    print(secrets1Recv)
    
    # Convert the secrets to integers
    secrets0RecvInt = []
    secrets1RecvInt = []
    for i in range(0, N):
        secrets0RecvInt.append(int(secrets0Recv[i], 2))
        secrets1RecvInt.append(int(secrets1Recv[i], 2))
        
    print(secrets0RecvInt)
    print(secrets1RecvInt)
    
    return secrets0RecvInt, secrets1RecvInt
    
    
# Either the sender or the receiver run this function
# Secrets0 and Secrets1 should both be lists of size N where Secrets0[i] and
# Secrets1[i] are pairs, so that the total number of secrets is 2N
# Each element in secrets0 and secrets1 should be binary numbers of length L,
# Eg. Secrets0[0] = 0b10000111, Secrets1[0] = 0b10100100 for L = 8
def PartialSecretExchangeB(secrets0, secrets1, sock, N, L):
    
    # Oblivious Transfer/Receive One Secret From Each Pair
    
    # The list of secrets received from the other side using Oblivious Transfer
    receivedSecretsOT = []
    
    for i in range(0, N):
        
        receivedSecret = obliviousTransfer12B(sock)
        receivedSecretsOT.append(receivedSecret)
        obliviousTransfer12A(int(secrets0[i], 2), int(secrets1[i], 2), sock)
    
    print("")
    print("Received Secrets using OT12:")
    print(receivedSecretsOT)
    
    # Convert the received secrets to binary
    receivedSecretOTBin = []
    for i in range(0, N):
        receivedSecretOTBin.append('0b' + bin(receivedSecretsOT[i])[2:].zfill(L))
    print(receivedSecretOTBin)
    
    # Transfer/Receive All Secrets Bit by Bit
    
    # Initialize the array of secrets (N pairs)
    secrets0Recv = ['0b' for x in range(N)]
    secrets1Recv = ['0b' for x in range(N)]
    
    # For each bit #
    for j in range(0, L):
        
        # Send and receive a bit for each secret
        secrets0Recv, secrets1Recv = receiveBit(secrets0Recv, secrets1Recv, receivedSecretOTBin, sock, N, j)
        sendBit(secrets0, secrets1, sock, N, j)
        
    
    print("")
    print("Received Secrets from bit by bit transfer:")
    print(secrets0Recv)
    print(secrets1Recv)
    
    # Convert the secrets to integers
    secrets0RecvInt = []
    secrets1RecvInt = []
    for i in range(0, N):
        secrets0RecvInt.append(int(secrets0Recv[i], 2))
        secrets1RecvInt.append(int(secrets1Recv[i], 2))
        
    print(secrets0RecvInt)
    print(secrets1RecvInt)
    
    return secrets0RecvInt, secrets1RecvInt
    

# Cheating PSE algorithm to check the cheat detection functionality
def PartialSecretExchangeB_CHEATING(secrets0, secrets1, incorrectSecrets0, incorrectSecrets1, sock, N, L):
    
    # Oblivious Transfer/Receive One Secret From Each Pair
    
    # The list of secrets received from the other side using Oblivious Transfer
    receivedSecretsOT = []
    
    for i in range(0, N):
        
        receivedSecret = obliviousTransfer12B(sock)
        receivedSecretsOT.append(receivedSecret)
        obliviousTransfer12A(int(secrets0[i], 2), int(secrets1[i], 2), sock)
    
    print("")
    print("Received Secrets using OT12:")
    print(receivedSecretsOT)
    
    # Convert the received secrets to binary
    receivedSecretOTBin = []
    for i in range(0, N):
        receivedSecretOTBin.append('0b' + bin(receivedSecretsOT[i])[2:].zfill(L))
    print(receivedSecretOTBin)
    
    # Transfer/Receive All Secrets Bit by Bit
    
    # Initialize the array of secrets (N pairs)
    secrets0Recv = ['0b' for x in range(N)]
    secrets1Recv = ['0b' for x in range(N)]
    
    # For each bit #
    for j in range(0, L):
        
        # Send and receive a bit for each secret
        secrets0Recv, secrets1Recv = receiveBit(secrets0Recv, secrets1Recv, receivedSecretOTBin, sock, N, j)
        sendBit(incorrectSecrets0, incorrectSecrets1, sock, N, j)
        
    
    print("")
    print("Received Secrets from bit by bit transfer:")
    print(secrets0Recv)
    print(secrets1Recv)
    
    # Convert the secrets to integers
    secrets0RecvInt = []
    secrets1RecvInt = []
    for i in range(0, N):
        secrets0RecvInt.append(int(secrets0Recv[i], 2))
        secrets1RecvInt.append(int(secrets1Recv[i], 2))
        
    print(secrets0RecvInt)
    print(secrets1RecvInt)
    
    return secrets0RecvInt, secrets1RecvInt