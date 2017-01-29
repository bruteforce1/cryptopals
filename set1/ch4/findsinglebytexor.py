#!/usr/bin/python3

"""
One of the 60-character strings in 4.txt has been encrypted by 
    single-character XOR.

Find it.

(Your code from #3 should help.)

"""

import argparse
import sys
from set1.ch3.singlebytexor import find_key


def find_msg(filename):
    score = 0
    keys = ('', '', '')
    with open(filename, 'r') as f:
        for line in f:
            line = line.rstrip('\n')
            line_keys = find_key(line)
            if line_keys[0] is not '' and score < line_keys[2]:
                score = line_keys[2]
                keys = (line, line_keys[0], line_keys[1])
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
    parser.add_argument('-f', '--inputfile', help='opt. encrypted input file',
                        default='4.txt')
    args = parser.parse_args()
    sys.exit(main(args.inputfile))
