#!/usr/bin/env python

import sys
import string
from BitVector import *                                                       
from collections import Counter

if len(sys.argv) is not 3:                                                    
    sys.exit('''Needs two command-line arguments, one for '''
             '''the message file and the other for the '''
             '''encrypted output file''')

PassPhrase = "I want to learn cryptograph and network security"               

BLOCKSIZE = 64                                                               
numbytes = BLOCKSIZE // 8     

def binToAsciiStr(binary):
    final_msg = ''
    for i in range(0, len(binary), 8):
        block = binary[i:i+8]
        final_msg+=chr(int(str(block),2))
    return final_msg


def binaryToAscii(binary):
    # msg = chr(int(str(binary),2))
    k = BitVector( bitstring = binary ) ^ BitVector( bitstring = bin(ord('e'))[2:] )
    return chr(int(str(k),2))

# print(binaryToAscii(bin(ord('h'))))
# print()
# print()

def hexToBinary(hex):
    binary = ""
    scale = 16 
    for i in range(0,len(hex)):
        char = bin(int(hex[i], scale))[2:].zfill(numbytes//2)   			# for each hex character make it a 4 bit binary
        binary+=char
    return binary

def secondMax(my_list):
    # print(my_list)
    freq = {} 
    for item in my_list: 
        if (item in freq): 
            freq[item] += 1
        else: 
            freq[item] = 1
    # print(freq)
    max1 = 0
    ans1 = -1
    for key, value in freq.items():
        if (value > max1):
            ans1 = key
    del freq[key]
    # print(freq)
    max2 = 0
    ans2 = -1
    for key, value in freq.items():
        if (value > max2):
            ans2 = key
    if(ans2 != -1):
        return ans2
    else:
        return ans1
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


numRows = BLOCKSIZE//8
charSize = 8
vigCArray = [[] for y in range(numRows)]
#vigCArray is a 2d matrix where each row represents a addition cipher

# print(pxorkBlocks[0]^pxorkBlocks[1]^pxorkBlocks[2])

for i in range(0,len( pxorkBlocks )):
    pxorkStr = str( pxorkBlocks[i] )
    # print(pxorkStr)
    count = 0
    for j in range(0, len(pxorkStr),charSize):
        temp = pxorkStr[j:j+charSize]
        vigCArray[count].append(temp)
        count = count+1

listAscii = string.printable

for i in range( len( listAscii ) ):
    char = listAscii[i]
    encKey = ''
    encKey2 = ''
    for i in range(8):
        maxOne = max( vigCArray[i], key = vigCArray[i].count )
        result = secondMax(vigCArray[i])
        result2 = maxOne
        # print(maxOne)
        result = str( BitVector(bitstring = result) ^ BitVector( textstring = char ) )
        result2 = str( BitVector(bitstring = result2) ^ BitVector( textstring = char ) )
        # print( binaryToAscii( result ) )
        encKey += result
        encKey2 += result2

    encKeyBVctr = BitVector( bitstring = encKey)
    encKeyBVctr2 = BitVector( bitstring = encKey2)
    # print(len(encKeyBVctr))
    # print(cipherBlocks[0] ^ cipherBlocks[1])
    ans1 = binToAsciiStr(pxorkBlocks[0] ^ encKeyBVctr)
    ans2 = binToAsciiStr(pxorkBlocks[1] ^ encKeyBVctr)
    ans12 = binToAsciiStr(pxorkBlocks[0] ^ encKeyBVctr2)
    ans22 = binToAsciiStr(pxorkBlocks[1] ^ encKeyBVctr2)
    # print(len(ans))
    # print('hmm')
    # print(ans1+ans2)
    # print('hmm2')
    print(ans12+ans22)