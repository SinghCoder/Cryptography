#!/usr/bin/env python

import sys
from BitVector import *                                                       

if len(sys.argv) is not 3:                                                    
    sys.exit('''Needs two command-line arguments, one for '''
             '''the message file and the other for the '''
             '''encrypted output file''')

PassPhrase = "I want to learn cryptograph and network security"               

BLOCKSIZE = 64                                                               
numbytes = BLOCKSIZE // 8     

def binaryToAscii(binary):
    final_msg = ''
    for i in range(0, len(binary), 8):
        block = binary[i:i+8]
        final_msg+=chr(int(str(block),2))	                                      
    return final_msg

def hexToBinary(hex):
    binary = ""
    scale = 16 
    for i in range(0,len(hex)):
        char = bin(int(hex[i], scale))[2:].zfill(numbytes//2)   			# for each hex character make it a 4 bit binary
        binary+=char
    return binary
                                               
#Open encrypted text file and read it
cipherFile = open(sys.argv[1],'r')
cipherText = cipherFile.read()

#convert cipher text to binary
cipherText = hexToBinary(cipherText)

cipherBlocks = []

for i in range(0,len(cipherText),BLOCKSIZE):
    cipherBlocks.append(BitVector(bitstring = cipherText[i:i+BLOCKSIZE]))


# Reduce the passphrase to a bit array of size BLOCKSIZE:
bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)                                   
for i in range(0,len(PassPhrase) // numbytes):                               
    textstr = PassPhrase[i*numbytes:(i+1)*numbytes]                          
    bv_iv ^= BitVector( textstring = textstr )                               

phraseEnc = bv_iv

# print(phraseEnc)
# print(cipherBlocks)

pxorkBlocks = []
cipherBlocks.insert(0,phraseEnc)
# print(len(cipherBlocks))

for i in range(len(cipherBlocks)-1,0,-1):
    pxork = cipherBlocks[i]^cipherBlocks[i-1]
    pxorkBlocks.insert(0,pxork)


numBlocks = BLOCKSIZE//8
charSize = 8
vigCArray = [[] for y in range(numBlocks)]
#vigCArray is a 2d matrix where each row represents a addition cipher

for i in range(0,len(pxorkBlocks)):
    pxorkStr = str(pxorkBlocks[i])
    count = 0
    for j in range(0, len(pxorkStr),charSize):
        vigCArray[count].append(pxorkStr[j:j+charSize])
        count = count+1

for i in range(8):
    result = max(vigCArray[i], key = vigCArray[i].count)
    print(binaryToAscii(result))