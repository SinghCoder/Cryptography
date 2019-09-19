#!/usr/bin/env python



###  Call syntax:
###
###       Encrypt.py  message_file.txt  output.txt
###
###  The encrypted output is deposited in the file `output.txt'

import sys
from BitVector import *                                                       #(A)

if len(sys.argv) is not 3:                                                    #(B)
    sys.exit('''Needs two command-line arguments, one for '''
             '''the message file and the other for the '''
             '''encrypted output file''')

PassPhrase = "I want to learn cryptograph and network security"                            #(C)

BLOCKSIZE = 64                                                                #(D)
numbytes = BLOCKSIZE // 8                                                     #(E)

# Reduce the passphrase to a bit array of size BLOCKSIZE:
bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)                                    #(F)
for i in range(0,len(PassPhrase) // numbytes):                                #(G)
    textstr = PassPhrase[i*numbytes:(i+1)*numbytes]                           #(H)
    bv_iv ^= BitVector( textstring = textstr )                                #(I)

# Get key from user:
key = None
if sys.version_info[0] == 3:                                                  #(J)
    key = input("\nEnter key: ")                                              #(K)
else:                                                                         
    key = raw_input("\nEnter key: ")                                          #(L)
key = key.strip()                                                             #(M)

# Reduce the key to a bit array of size BLOCKSIZE:
key_bv = BitVector(bitlist = [0]*BLOCKSIZE)                                   #(N)
for i in range(0,len(key) // numbytes):                                       #(O)
    keyblock = key[i*numbytes:(i+1)*numbytes]                                 #(P)
    key_bv ^= BitVector( textstring = keyblock )                              #(Q)

# Create a bitvector for storing the ciphertext bit array:
msg_encrypted_bv = BitVector( size = 0 )                                      #(R)

# Carry out differential XORing of bit blocks and encryption:
previous_block = bv_iv                                                        #(S)
bv = BitVector( filename = sys.argv[1] )                                      #(T)
while (bv.more_to_read):                                                      #(U)
    bv_read = bv.read_bits_from_file(BLOCKSIZE)                               #(V)
    if len(bv_read) < BLOCKSIZE:                                              #(W)
        bv_read += BitVector(size = (BLOCKSIZE - len(bv_read)))               #(X)
    bv_read ^= key_bv                                                         #(Y)
    bv_read ^= previous_block                                                 #(Z)
    previous_block = bv_read.deep_copy()                                      #(a)
    msg_encrypted_bv += bv_read                                               #(b)

# Convert the encrypted bitvector into a hex string:    
outputhex = msg_encrypted_bv.get_hex_string_from_bitvector()                  #(c)

# Write ciphertext bitvector to the output file:
FILEOUT = open(sys.argv[2], 'w')                                              #(d)
FILEOUT.write(outputhex)                                                      #(e)
FILEOUT.close()                                                               #(f)
