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

#list of all english letters including space
letters = list(string.ascii_lowercase)
letters = letters + list(string.ascii_uppercase) 
letters.append(' ')

"""
    Input:  binary string
    Output: equivalent string of ascii characters
"""
def binStrToAsciiStr(binary):
    final_msg = ''
    for i in range(0, len(binary), 8):
        block = binary[i:i+8]
        final_msg+=chr(int(str(block),2))
    return final_msg

"""
    Input:  binary string corresponding to a character
    Output: character it corresponds to
"""
def binaryToAscii(binary):
    k = BitVector( bitstring = binary ) ^ BitVector( bitstring = bin(ord('e'))[2:] )
    return chr(int(str(k),2))

"""
    Input:  string of hexadecimal digits
    Output: string corresponding to binary equivalent to each character
"""
def hexToBinary(hex):
    binary = ""
    scale = 16 
    for i in range(0,len(hex)):
        char = bin(int(hex[i], scale))[2:].zfill(numbytes//2)   			# for each hex character make it a 4 bit binary
        binary+=char
    return binary

"""
    Input:  list of binary strings
    Output: binary string with frequency second maximum/ max freq string if only one unique string is present
"""
def secondMax(my_list):
    freq = {}   #dictionary to store frequency of each element
    for item in my_list: 
        if (item in freq): 
            freq[item] += 1
        else: 
            freq[item] = 1
    max1 = 0    #maximum element
    ans1 = -1
    for key, value in freq.items():
        if (value > max1):
            ans1 = key
    
    del freq[key]   #remove the max in order to get second maximum
    
    max2 = 0    #second maximum element
    ans2 = -1
    for key, value in freq.items():
        if (value > max2):
            ans2 = key
    if(ans2 != -1):     #if only one element was in dictionary return first one only
        return ans2
    else:
        return ans1

"""
    Input:  string of ascii characters
    Output: score denoting number of chracters which are alphabets or space
"""
def findScore(temp):
    count = 0
    for i in range( len( temp ) ):
        if temp[i] in letters:
            count += 1

    return count


#Open encrypted text file and read it
cipherFile = open(sys.argv[1],'r')
cipherText = cipherFile.read()

#convert cipher text to binary
cipherText = hexToBinary(cipherText)

# Reduce the passphrase to a bit array of size BLOCKSIZE:
bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)                                   
for i in range(0,len(PassPhrase) // numbytes):                               
    textstr = PassPhrase[i*numbytes:(i+1)*numbytes]                          
    bv_iv ^= BitVector( textstring = textstr )                               

phraseEnc = bv_iv

#divide the cipher binary string to blocks of BLOCKSIZE
cipherBlocks = []

for i in range(0,len(cipherText),BLOCKSIZE):
    cipherBlocks.append(BitVector(bitstring = cipherText[i:i+BLOCKSIZE]))

cipherBlocks.insert(0,phraseEnc)

#array storing xors of plaintext blocks with key
pxorkBlocks = []
for i in range(len(cipherBlocks)-1,0,-1):
    pxork = cipherBlocks[i]^cipherBlocks[i-1]
    pxorkBlocks.insert(0,pxork)

numRows = BLOCKSIZE//8
charSize = 8
#vigCArray is a 2d matrix where each row represents a addition cipher
vigCArray = [[] for y in range(numRows)]
for i in range(0,len( pxorkBlocks )):
    pxorkStr = str( pxorkBlocks[i] )
    count = 0
    for j in range(0, len(pxorkStr),charSize):
        temp = pxorkStr[j:j+charSize]
        vigCArray[count].append(temp)
        count = count+1


#BRUTEFORCE ATTACK STARTS
#Same as logic of Vigenere Cipher, but here try to map to each possible english letter including space and find out score
#The character giving maximum score would be probably the one mapped, so take it

listAscii = string.printable  #all possible characters right now in reduced key
maxScore = 0
finalEncKey = ''    #The most probable reduced key
for i in range( len( listAscii ) ):
    char = listAscii[i]
    encKey = ''     #key corresponding to taking charcater with maximum frequency
    encKey2 = ''    #key corresponding to taking charcater with second maximum frequency
    for i in range(8):
        
        result = max( vigCArray[i], key = vigCArray[i].count )
        result = str( BitVector(bitstring = result) ^ BitVector( textstring = char ) )  # as in vigenere cipher we map max occuring character to e and 
                                                                                        #add the diff, here map to all possible characters and xor the values
        encKey += result

        result2 = secondMax(vigCArray[i])
        result2 = str( BitVector(bitstring = result2) ^ BitVector( textstring = char ) )
        encKey2 += result2

    encKeyBVctr = BitVector( bitstring = encKey)
    ans1 = binStrToAsciiStr(pxorkBlocks[0] ^ encKeyBVctr)   #To get score right now only two blocks are considered, to improve accuracy, increase no of blocks
    ans2 = binStrToAsciiStr(pxorkBlocks[1] ^ encKeyBVctr)

    firstScore = findScore(ans1+ans2)
    if(maxScore < firstScore):
        maxScore = firstScore
        finalEncKey = encKeyBVctr

    encKeyBVctr2 = BitVector( bitstring = encKey2)
    ans12 = binStrToAsciiStr(pxorkBlocks[0] ^ encKeyBVctr2)
    ans22 = binStrToAsciiStr(pxorkBlocks[1] ^ encKeyBVctr2)
    
    secondScore = findScore(ans12+ans22)
    if(maxScore < secondScore):
        maxScore = secondScore
        finalEncKey = encKeyBVctr2

for i in range( len( pxorkBlocks ) ):
    mystring = binStrToAsciiStr( str( finalEncKey ^ pxorkBlocks[i] ) )
    print( mystring, end='')