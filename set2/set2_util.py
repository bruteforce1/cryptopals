#!/usr/bin/python3

"""
This module is used to define functions as they are worked through in 
 each of the challenges.  Functions will be added after the challenge
 is completed for use in future challenges.
"""

import string
import sys

def check_pad_input(message,bl):
    if type(message).__name__ == 'str':
        m = message.encode('utf-8')
    elif type(message).__name__ == 'bytes':
        m = message
    else:
        print('message is unexpected type.')
        return ('',-1)
    
    try: 
        b = int(bl)
        if 1 < b and b <= 32:
            return (m,b)
        print('PKCS7 block size must be between 1 and 32 bytes')
    except ValueError:
        print('Not a valid integer')
    return (m,-1)

def pad_pkcs7(message, block=16):
    m, bl = check_pad_input(message, block)
    assert(bl != -1), 'Invalid input.'
    pad = bl
    if len(m) % bl:
        pad = bl - len(m) % bl
    ret = m + bytes([pad]) * pad
    return ret

def unpad_pkcs7(message, block=16):
    m, bl = check_pad_input(message, block)
    assert(bl != -1), 'Invalid input.'
    assert(len(m) % int(bl) == 0), 'Message length not evenly divided.'
    pad = int(m[-1])
    assert(m[-pad:] == bytes((pad,))*pad), 'Incorrect padding.'
    return m[:-pad]
