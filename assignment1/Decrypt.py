#!/usr/bin/env python



###  Call syntax:
###
###       Dncrypt.py  encrypted_file.txt  output.txt
###
###  The decrypted output is deposited in the file `output.txt'

import sys
from BitVector import *                                                       #(A)

if len(sys.argv) is not 3:                                                    #(B)
    sys.exit('''Needs two command-line arguments, one for '''
             '''the message file and the other for the '''
             '''encrypted output file''')

PassPhrase = "I want to learn cryptograph and network security"               #(C)

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

#Open decrypted text file and read it
cipherFile = open(sys.argv[1],'r')
cipherText = cipherFile.read()

# Create a bitvector for storing the ciphertext bit array:
msg_decrypted_bv = BitVector( size = 0 )                                      #(R)

#get binary string from the hexadecimal cipher string
ciph_bv = ""
scale = 16 
for i in range(0,len(cipherText)):
	char = bin(int(cipherText[i], scale))[2:].zfill(numbytes//2)   			# for each hex character make it a 4 bit binary
	ciph_bv+=char

# Carry out differential XORing of bit blocks and decryprion:
previous_block = bv_iv                                                        #(S)
																			 #(T)
for i in range(0,len(ciph_bv), BLOCKSIZE):
#take 64 bit blocks from cipher text and apply decryption algo
	cipherblock = ciph_bv[i:i+BLOCKSIZE]                         			  #(U)
	bv_read = BitVector(bitstring = str(cipherblock))                         #(V)
# store encrypted previous block bcz next block is decrypted using it
	prev_encrypted_block = bv_read
	
	if len(bv_read) < BLOCKSIZE:                                              #(W)
		bv_read += BitVector(size = (BLOCKSIZE - len(bv_read)))               #(X)

	bv_read ^= key_bv                                                         #(Y)
	bv_read ^= previous_block                                                 #(Z)
	previous_block = prev_encrypted_block                                     #(a)
	msg_decrypted_bv += bv_read                                               #(b)

# convert the binary string to ascii string to get final message
final_msg = ''
for i in range(0, len(msg_decrypted_bv), 8):
	block = msg_decrypted_bv[i:i+8]
	#print(block)
	final_msg+=chr(int(str(block),2))	                                      #(f)
	
	
# Write decrypted text to the output file:
FILEOUT = open(sys.argv[2], 'w')                                              #(d)
FILEOUT.write(final_msg)                                                      #(e)
FILEOUT.close()       
	
	
	
