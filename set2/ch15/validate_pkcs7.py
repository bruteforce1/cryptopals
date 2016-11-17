#!/usr/bin/python3

"""
 Write a function that takes a plaintext, determines if it has
 valid PKCS#7 padding, and strips the padding off.

The string:

"ICE ICE BABY\x04\x04\x04\x04"

... has valid padding, and produces the result "ICE ICE BABY".

The string:

"ICE ICE BABY\x05\x05\x05\x05"

... does not have valid padding, nor does:

"ICE ICE BABY\x01\x02\x03\x04"

If you are writing in a language with exceptions, like Python or
 Ruby, make your function throw an exception on bad padding.

Crypto nerds know where we're going with this. Bear with us. 
"""

import argparse
import string
import sys
sys.path.insert(0, './utils')
from cpset2 import pkcs7_padding, PaddingError

def validate_pkcs7(test):
    try:
        pkcs7_padding(test,16,0)
        print('Padding is correct')
    except PaddingError:
        print('Message has a padding error.')

def test_pkcs7():
    test1 = b'ICE ICE BABY\x04\x04\x04\x04'
    print('Test 1: \"ICE ICE BABY\\x04\\x04\\x04\\x04\"')
    validate_pkcs7(test1)

    test1 = b'ICE ICE BABY\x05\x05\x05\x05'
    print('Test 2: \"ICE ICE BABY\\x05\\x05\\x05\\x05\"')
    validate_pkcs7(test1)

    test1 = b'ICE ICE BABY\x01\x02\x03\x04'
    print('Test 1: \"ICE ICE BABY\\x01\\x02\\x03\\x04\"')
    validate_pkcs7(test1)


def main():
    test_pkcs7()
    return 0 

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Demonstrates PKCS#7 validation using a couple of test scenarios.'
        )
    args = parser.parse_args()
    sys.exit(main())
