#!/usr/bin/env python
import sys
import Encrypt
import Decrypt
import random
from BitVector import *                                                       

iptable = [7, 6, 4, 0, 2, 5, 1, 3]
ipinvtable = [3, 6, 4, 7, 2, 5, 1, 0]
fkPermTable = [0 ,2 , 1, 3, 0, 1, 2, 3]
fklastPermTable = [1, 0, 3, 2]
sboxperm0 = [[1, 0, 2, 3], [3, 1, 0 ,2], [2, 0 , 3, 1], [1, 3, 2 ,0]]
sboxperm1 = [[0, 3, 1 , 2], [3, 2, 0, 1], [1, 0 , 3, 2], [2, 1, 3 , 0]]
deltaxS0 = BitVector(bitstring = '0010')
deltayS0 = BitVector(bitstring = '10')

deltaxS1 = BitVector(bitstring = '0100')
deltayS1 = BitVector(bitstring = '10')

deltaxRnd1 = BitVector(bitstring = '00100100')

deltauRnd1 = BitVector( bitstring = '00000100')

deltapInp = BitVector( bitstring = '00000100')  #initial permutation is such that the deltap and deltau are same here
deltayRnd1 = BitVector(bitstring = '1010')

deltavRnd1 = BitVector( bitstring = '01000101')
keycount = {}

diffDistrS0 = [
                [16, 0, 0, 0],
                [0, 8, 4, 4],
                [0, 4, 12, 0],
                [4, 4, 0, 8],
                [0, 4, 0, 12],
                [4, 4, 8, 0],
                [0, 8, 4, 4],
                [8, 0, 4, 4],
                [2, 2, 10, 2],
                [4, 4, 0, 8],
                [10, 2, 2, 2],
                [0, 8, 4, 4],
                [2, 10, 2, 2],
                [8, 0, 4, 4],
                [2, 2, 2, 10],
                [4, 4, 8, 0]
]

diffDistrS1 = [
                [16, 0, 0, 0],
                [2, 8, 2, 4],
                [0, 6, 4, 6],
                [4, 2, 8, 2],
                [2, 0, 10, 4],
                [2, 4, 2, 8],
                [0, 10, 0, 6],
                [8, 2, 4, 2],
                [4, 6, 0, 6],
                [8, 2, 4, 2],
                [2, 0, 10, 4],
                [0, 6, 4, 6],
                [6, 0, 6, 4],
                [6, 0, 6, 4],
                [11, 3, 2, 0],
                [2, 8, 2, 4]
]

for k in range(256):
    keycount[k] = 0

def fkey( inp, key ):
    inpext = BitVector(size = 8)
    for i in range(len(inpext)):
        inpext[i] = inp[fkPermTable[i]]
    epxork = inpext ^ key
    epxorkL, epxorkR = epxork[0:len(epxork)//2], epxork[len(epxork)//2 : len(epxork)]

    rowL = 2* int(epxorkL[0]) + int(epxorkL[3])
    colL = 2* int(epxorkL[1]) + int(epxorkL[2])
    
    rowR = 2* int(epxorkR[0]) + int(epxorkR[3])
    colR = 2* int(epxorkR[1]) + int(epxorkR[2])

    outpL = BitVector(intVal = sboxperm0[rowL][colL], size = 2)
    outpR = BitVector(intVal = sboxperm1[rowR][colR], size = 2)
    # print("fkeyout: ", [str(outpL), str(outpR)])
    outpb4perm = BitVector(bitstring = str(outpL)+str(outpR))
    finaloutp = BitVector(size = 4)
    for i in range(4):
        finaloutp[i] = outpb4perm[fklastPermTable[i]]
    return finaloutp


def main():
    for count in range(256):
        pt = BitVector( intVal = count,size = 8)
        # print('Processing pt : ', pt)
        ptdash = pt ^ deltapInp
        
        # print("pt ",pt)
        # print("ptdash ",ptdash)
        
        ptfilename = "tempptfile.txt"
        ptfile = open(ptfilename, 'w',encoding="utf-8")
        ptfile.write(str(chr(int(str(pt),2)))+str(chr(int(str(ptdash),2))))
        ptfile.close()
        ctfilename = "tempctfile.txt"
        Encrypt.startenc(ptfilename, ctfilename,None)
        
        ctfile = open(ctfilename, "r")
        ct = BitVector(bitstring = ctfile.read(8))
        ctfile.close()
        ctfile = open(ctfilename, "r")
        ctdash = BitVector( bitstring = ctfile.read(16)[8:])
        ctfile.close()
        ctXorCtdash = ct ^ ctdash
        # print("pt^ptdash = ", pt^ptdash)
        # print("ct^ctdash = ", ct^ctdash)
        lastRndOutpCt = BitVector(bitstring = "00000000")
        lastRndOutpCtdash = BitVector(bitstring = "00000000")
        for k in range(8):
            lastRndOutpCt[k] = ct[ iptable[k] ]
            lastRndOutpCtdash[k] = ctdash[ iptable[k] ]
        # print(lastRndOutp)
        
        # l2xor = lastRndOutp[0:4]
        # r2xor = lastRndOutp[4:]
        # r1xor = l2xor
        
        l2ct = lastRndOutpCt[0:4]
        l2ctdash = lastRndOutpCtdash[0:4]
        r2ct = lastRndOutpCt[4:]
        r2ctdash = lastRndOutpCtdash[4:]
        r1ct = l2ct
        r1ctdash = l2ctdash

        #Now do exhaustive search on subkey k2
        for k in range(256):
            k2 = BitVector(intVal = k, size = 8)
            # print("trying key : ",k," : ",k2)
            l1ct = r2ct ^ fkey(r1ct,k2)
            l1ctdash = r2ctdash ^ fkey(r1ctdash,k2)
            l1xor = l1ct ^ l1ctdash
            r1xor = r1ct ^ r1ctdash
            # print('l1+r1 xors : ',str(l1xor)+str(r1xor))
            if(BitVector(bitstring = str(l1xor) + str(r1xor) ) == deltavRnd1):
                keycount[k] = keycount[k] + 1
                print("Match Found..")
                # print("key : ",k," : ",k2)
        
    maxFreq = 0
    bestkey = -1
    for i in range(256):
        if(keycount[i] > maxFreq):
            maxFreq = keycount[i]
            bestkey = i
    if(bestkey >= 0):
        bs = BitVector(intVal = bestkey, size = 8)
        print("Best found key : ",bs)
    else :
        print("Best found key : ",bestkey)
if __name__ == "__main__":
    main()