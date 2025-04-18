#!/usr/bin/env python3
import sys
from des import DesKey

def test_des(key_text, message):
    initial = bytearray(message)[:8]
    initial = bytes(initial)
    key = DesKey(key_text)
    print("======================")
    print(f"DES: {key.is_single()}") # is it single DES or triple 3DES
    encrypted = key.encrypt(message)
    # decrypted = key.decrypt(encrypted)

    print(f"> the key is")
    print(key_text)
    print('\n'.join(format(byte, '08b') for byte in key_text))
    print(f"and the size in bytes is {len(key_text)}")
    print(f"> the initial value is")
    print('\n'.join(format(byte, '08b') for byte in initial))
    print("> the message is")
    print(message)
    print('\n'.join(format(byte, '08b') for byte in message))
    print(f"and the size in bytes is {len(message)}")
    print("> the encrypted message is:")
    print(encrypted)
    print('\n'.join(format(byte, '08b') for byte in encrypted))
    # print("> the decrypted message is:")
    # print(decrypted)
    # print('\n'.join(format(byte, '08b') for byte in decrypted))
    print("======================")

####### test output when key and message are 0s.
# keyA = b"\x00"*8
# initialA = b"\x00"*8
# messageA = b"\x00"*32
# test_des(keyA, messageA, initialA)

####### test round keys of a key of all 1s.
# keyB = b"\xFF"*8
# initialB = b"\xFF"*8
# messageB = b"\xFF"*32
# test_des(keyB, messageB, initialB)

####### test output message is 0s but changed one bit to 1.
keyC = b"\x00"*8
initialC = b"\x00"*8
messageC = b"\x00"*32
modMessageC = bytearray(messageC)
modMessageC[0] ^= 0b01000000
# test_des(keyC, bytes(modMessageC))

def is_weak_key(key, message):
    key_other = 0x0001000010001000.to_bytes(8, byteorder='big')
    key_des = DesKey(key)
    key_des_other = DesKey(key_other)
    encrypted = key_des.encrypt(message)
    decrypted = key_des_other.encrypt(encrypted)
    print("======================")
    print("> the original message is:")
    print(message)
    print('\n'.join(format(byte, '08b') for byte in message))
    print("======================")
    print("> the encrypted message is:")
    print(encrypted)
    print('\n'.join(format(byte, '08b') for byte in encrypted))
    print("======================")
    print("> the decrypted message is:")
    print(decrypted)
    print('\n'.join(format(byte, '08b') for byte in decrypted))
    print("======================")
    print(f"Is the key {key} weak? {message == decrypted}")
    return message == decrypted



# weak_key_A= b"\x00"*8
# initial = b"\x00"*8
# weak_key_B = 0xE1E1E1E1F0F0F0F0.to_bytes(8, byteorder='big')
# result = is_weak_key(weak_key_A, bytes(modMessageC), initial)
# print(f"The key {weak_key_A} is weak {result}")
# result = is_weak_key(weak_key_B, bytes(modMessageC))
# print(f"The key {weak_key_B} is weak {result}")
#
#### DES weak keys produce sixteen identical subkeys.
#### encrypting twice produces the original plaintext

weak_key_1 = 0x0000000000000000
weak_key_2 = 0x1F1F1F1F0E0E0E0E
weak_key_3 = 0xE0E0E0E0F1F1F1F1
weak_key_4 = 0xFEFEFEFEFEFEFEFE

weak_key_5 = 0x1111111111111111
weak_key_6 = 0x0000000011111111
weak_key_7 = 0x1111111100000000
