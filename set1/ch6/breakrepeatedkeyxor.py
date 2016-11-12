#!/usr/bin/python3

"""
There's a file here. It's been base64'd after being encrypted with
 repeating-key XOR.

Decrypt it.

Here's how:

  1 Let KEYSIZE be the guessed length of the key; try values from 2 to 
    (say) 40.
  2 Write a function to compute the edit distance/Hamming distance 
    between two strings. The Hamming distance is just the number of 
    differing bits. The distance between:

    this is a test

    and

    wokka wokka!!!

    is 37. Make sure your code agrees before you proceed.
  3 For each KEYSIZE, take the first KEYSIZE worth of bytes, and the
    second KEYSIZE worth of bytes, and find the edit distance between
    them. Normalize this result by dividing by KEYSIZE.
  4 The KEYSIZE with the smallest normalized edit distance is probably
    the key. You could proceed perhaps with the smallest 2-3 KEYSIZE
    values. Or take 4 KEYSIZE blocks instead of 2 and average the
    distances.
  5 Now that you probably know the KEYSIZE: break the ciphertext into
    blocks of KEYSIZE length.
  6 Now transpose the blocks: make a block that is the first byte of
    every block, and a block that is the second byte of every block,
    and so on.
  7 Solve each block as if it was single-character XOR. You already
    have code to do this.
  8 For each block, the single-byte XOR key that produces the best
    looking histogram is the repeating-key XOR key byte for that block.
    Put them together and you have the key.

This code is going to turn out to be surprisingly useful later on.
 Breaking repeating-key XOR ("Vigenere") statistically is obviously an
 academic exercise, a "Crypto 101" thing. But more people "know how" to
 break it than can actually break it, and a similar technique breaks
 something much more important. 
"""

import argparse
import binascii
import math
import string
import sys
sys.path.insert(0, 'set1/ch3')
from singlebytexor import find_key

def decrypt_repeated_key_xor(filename):

    def decrypt_rkx(msg, keysize):
        #step 5
        blocks = [msg[i:i + keysize] for i in range(0, len(msg), keysize)] 

        #step 6
        xorkeys = ''
        newblocks = []
        for x in range(0,keysize):
            line = bytearray()
            for b in blocks:
                if x < len(b):
                    line.append(b[x])
            l = binascii.hexlify(line).decode('utf-8')

            #step 7
            ret = find_key(l) 
            if not ret[0]:
                return ('','')
            xorkeys += ret[0]
            newblocks.append(ret[1])
        ans = ''

        #step 9
        for x in range(0,len(newblocks[0])):
            for nb in newblocks:
                if x < len(nb):
                    ans += nb[x]
        return (xorkeys,str(ans))

    def hammingdistance(str1, str2): 
        #step 2
        if len(str1) != len(str2):
            print('Invalid Hamming Distance check')
            exit(1)
        bstr1 = ''.join(format(x, '08b') for x in str1)
        bstr2 = ''.join(format(x, '08b') for x in str2)
        return sum(x != y for x, y in zip(bstr1, bstr2))

    def sort_key_sizes(crypt, max_len=40): 
        #step 3
        KEYSIZE = range(2, max_len)

        #step 4
        sizes = []
        for k in KEYSIZE:
             maxavs = math.floor(len(crypt)/k)
             totsize = 0
             inc = 1
             for x in range(2,maxavs,2):
                 if x*k > len(crypt):
                     break
                 str1 = crypt[(x-2)*k:(x-1)*k]
                 str2 = crypt[(x-1)*k:x*k]
                 size = hammingdistance(str1,str2) / float(k)
                 totsize += size
                 avsize = totsize / float(inc)
                 inc += 1
             sizes.append((k,avsize))
        sizes.sort(key=lambda x: x[1])
        return [size[0] for size in sizes]

    crypt = ''
    with open(filename,'r') as f:
        for line in f:
            crypt += line.rstrip()
    cry = binascii.a2b_base64(crypt)
    keysize = sort_key_sizes(cry)[0]
    return decrypt_rkx(cry,keysize)

def main(filename):
    key, ans = decrypt_repeated_key_xor(filename)
    if key:
        print('Key: ' + key)
        print('Decrypted:')
        print(ans)
        return 0
    print('Error.')
    return -1

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Takes a message encrypted with repeating key XOR, and \
        finds the key and decrypts it.'
        )
    parser.add_argument('inputfile', help='file with contents encrypted by \
        repeating key XOR and base64 encoded')
    args = parser.parse_args()
    
    sys.exit(main(args.inputfile))
