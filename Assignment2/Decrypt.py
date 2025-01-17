#!/usr/bin/env python
###  Call syntax:
###
###       Encrypt.py  message_file.txt  output.txt
###
###  The encrypted output is deposited in the file `output.txt'

import sys
from BitVector import *                                                       

iptable = [7, 6, 4, 0, 2, 5, 1, 3]
ipinvtable = [3, 6, 4, 7, 2, 5, 1, 0]
keyiptable = [9, 7, 3, 8, 0, 2, 6, 5, 1, 4]
fkPermTable = [0 ,2 , 1, 3, 0, 1, 2, 3]
fklastPermTable = [1, 0, 3, 2]
subkeyPermTable = [3, 1, 7, 5, 0, 6, 4, 2]
sperm0 = [[1, 0, 2, 3], [3, 1, 0 ,2], [2, 0 , 3, 1], [1, 3, 2 ,0]]
sperm1 = [[0, 3, 1 , 2], [3, 2, 0, 1], [1, 0 , 3, 2], [2, 1, 3 , 0]]

def ip(block):
    perm = BitVector(size = len(block))
    for i in range(len(block)):
        perm[i] = block[ iptable[ i ] ]
    return perm

def ipinv(block):
    perm = BitVector(size = len(block))
    for i in range(len(block)):
        perm[i] = block[ ipinvtable[ i ] ]
    return perm

def getkeys(key):
    perm = BitVector(size = len(key))
    for i in range(len(key)):
        perm[i] = key[ keyiptable[ i ] ]
    
    # print("keyperm: ", perm)
    permL, permR =  perm[0:5], perm[5:10]
    # print("permL: ", permL)
    permL = permL[1:5] + BitVector(intVal = permL[0])
    # permL = permL << 1
    # if(permL[0] == 1):
    #     permL[4] = 0
    # print("permL<<1: ", permL)
    permR = permR[1:5] + BitVector(intVal = permR[0])
    # permR = permR << 1
    # if(permR[0] == 1):
    #     permR[4] = 0

    key1ext = permL + permR
    # print("permKey: ",key1ext)
    key1 = BitVector( size = 8)
    for i in range(len(key1)):
        key1[i] = key1ext[subkeyPermTable[i]]

    # permL = permL << 2
    # permR = permR << 2
    permL = permL[2:5]+permL[0:2]
    permR = permR[2:5]+permR[0:2]

    key2ext = permL + permR
    key2 = BitVector( size = 8)
    for i in range(len(key2)):
        key2[i] = key2ext[subkeyPermTable[i]]
    
    return key1, key2

def fkey( inp, key ):
    inpext = BitVector(size = 8)
    for i in range(len(inpext)):
        inpext[i] = inp[fkPermTable[i]]
    epxork = inpext ^ key
    epxorkL, epxorkR = epxork[0:len(epxork)//2], epxork[len(epxork)//2 : len(epxork)]

    outpL = BitVector(size = 2)
    outpR = BitVector(size = 2)
    
    rowL = 2* int(epxorkL[0]) + int(epxorkL[3])
    colL = 2* int(epxorkL[1]) + int(epxorkL[2])
    
    rowR = 2* int(epxorkR[0]) + int(epxorkR[3])
    colR = 2* int(epxorkR[1]) + int(epxorkR[2])

    outpL = BitVector(intVal = sperm0[rowL][colL], size = 2)
    outpR = BitVector(intVal = sperm1[rowR][colR], size = 2)

    # print("fkeyout: ", [str(outpL), str(outpR)])
    outpb4perm = outpL+outpR
    finaloutp = BitVector(size = 4)
    for i in range(4):
        finaloutp[i] = outpb4perm[fklastPermTable[i]]
    return finaloutp

def decBlock(msgblock, key):
    inperm = ip( msgblock )
    print("msgBlock: ",msgblock)
    print("inperm: ",inperm)
    inpermL = inperm[0 : len(inperm)//2]
    inpermR = inperm[len(inperm)//2 : len(inperm)]

    key1, key2 = getkeys(key)
    print("keys: ",[str(key1), str(key2)])
    rnd1outpL = inpermR 
    
    rnd1outpR =  fkey( inpermR, key2 ) ^ inpermL 
    rnd1outp = rnd1outpL + rnd1outpR
    print("rnd1outp: ",rnd1outp)
    
    rnd2outpL = fkey( rnd1outpR, key1 ) ^ rnd1outpL
    rnd2outpR = rnd1outpR

    rnd2outp = rnd2outpL + rnd2outpR
    
    print("rnd2outp: ",rnd2outp)

    pt = ipinv( rnd2outp )

    print("pt = ", pt)
    return pt


BLOCKSIZE = 8                                     
numbytes = BLOCKSIZE // 8                                                     

def startdec(ctfile, ptfile):
    # Get key from user:
    key = None
    if sys.version_info[0] == 3:                                                  
        key = input("\nEnter key: ")                                              
    else:                                                                         
        key = raw_input("\nEnter key: ")                                          
    key = key.strip()                                                             

    # Convert key to bit vector
    key_bv = BitVector(bitstring = key) 

    # print(key_bv)

    # Create a bitvector for storing the ciphertext bit array:
    encmsg_bv = BitVector( size = 0 )                                      
    cipherFile = open(ctfile,'r')
    cipherText = cipherFile.read()
    final_msg = ''

    for i in range(0,len(cipherText),BLOCKSIZE):
        msgblk_bv = BitVector( bitstring = cipherText[i:i+BLOCKSIZE] )
        print("msgblk: ",msgblk_bv)    
        decblk = decBlock(msgblk_bv, key_bv) 
        final_msg += chr(int(str(decblk),2))

    FILEOUT = open(ptfile, 'w')                                              
    FILEOUT.write(final_msg)
    FILEOUT.close()                                            

def main():
    if len(sys.argv) is not 3:                                                    
        sys.exit('''Needs two command-line arguments, one for '''
                '''the message file and the other for the '''
                '''encrypted output file''')
    startdec(sys.argv[1], sys.argv[2])