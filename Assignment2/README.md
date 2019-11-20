# **Assignment 2 - Differential Cryptanalysis on S-DES**

S-DES is a reduced version of the DES algorithm. It has similar properties to DES but deals with a much smaller block and key size (operates on 8-bit message blocks with a 10-bit key). It has 2 rounds. The 10-bit key is used to generate 2 different blocks of 8-bit subkeys where each block is used in a particular iteration.

# Objective: 
- To perform differential cryptanalysis on Simplified S-Box. 
- To extract the main key, round1 subkey, and round2 subkey. 

### Files included:
- Encryption code
- Decryption code 
- Differential cryptanalysis crack code

### Dependencies
- BitVector library, python

### To run 
- ```python
        python Encrypt.py <plaintext filename> <filename to contain ciphertext>
  ```


### *References*

- [Appendix G, Simplified DES - William Stallings](http://mercury.webster.edu/aleshunas/COSC%205130/G-SDES.pdf)
- [Cryptanalysis of S-DES, *University of Sheffield Centre, Taylor’s College*](https://eprint.iacr.org/2002/045.pdf)