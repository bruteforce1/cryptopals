#!/usr/bin/python3

"""
One of the 60-character strings in 4.txt has been encrypted by 
    single-character XOR.

Find it.

(Your code from #3 should help.)

"""

import argparse
import base64
import string
import sys
sys.path.insert(0, 'set1/ch3')
from singlebytexor import find_key

def find_msg(filename):
    score = 0
    keys = ('', '', '')
    with open(filename, 'r') as f:
        for line in f:
            line = line.rstrip('\n')
            linekeys = find_key(line)
            if linekeys[0] is not '' and score < linekeys[2]:
                score = linekeys[2]
                keys = (line, linekeys[0], linekeys[1])
    return keys

def main(filename):
    ret = find_msg(filename)
    if ret[0]:
        print('Line: ' + ret[0] + '\nKey: ' + ret[1] + '\nPT: ' + ret[2])
        return 0
    print("Nothing found.")
    return -1

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Searches through list of encrypted data to find string \
        encrypted by repeating key xor.'
        )
    parser.add_argument('filename', help='encrypted input file')
    args = parser.parse_args()
    sys.exit(main(args.filename))
