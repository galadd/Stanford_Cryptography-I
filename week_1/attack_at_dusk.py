"""
Suppose you are told that the one time pad encryption of the message 
"attack at dawn" is 09e1c5f70a65ac519458e7e53f36

(the plaintext letters are encoded as 8-bit ASCII and the given ciphertext is written in hex). 
What would be the one time pad encryption of the message "attack at dusk" under the same OTP key?
"""

import binascii

def main():
    text = "attack at dawn"
    pt = string_to_binary(text)
    hex_str = "6c73d5240a948c86981bc294814d"
    ct = hex_to_binary(hex_str)

    k = xor(pt, ct)

    text = "attack at dusk"
    pt = string_to_binary(text)
    ct_bin = xor(pt, k)
    ct = binary_to_hex(ct_bin)

    print(ct)

def string_to_binary(text):
    result = ""
    for c in text:
        bin_val = bin(ord(c))[2:].zfill(8)
        result += bin_val
    return result.encode()

def hex_to_binary(hex_str):
    bytes_val = binascii.unhexlify(hex_str)
    result = ""
    for byte in bytes_val:
        bin_val = bin(byte)[2:].zfill(8)
        result += bin_val
    return result.encode()

def binary_to_hex(binary_str):
    binary_str = binary_str.replace(b" ", b"") # Remove spaces
    bytes_val = bytearray()
    for i in range(0, len(binary_str), 8):
        byte_str = binary_str[i:i+8]
        byte_val = int(byte_str, 2)
        bytes_val.append(byte_val)
    hex_str = binascii.hexlify(bytes_val)
    return hex_str.decode("utf-8")

def xor(bin_str1, bin_str2):
    if len(bin_str1) != len(bin_str2):
        raise ValueError("Binary strings must be of equal length")
    result = bytearray(len(bin_str1))
    for i in range(len(bin_str1)):
        if bin_str1[i] == bin_str2[i]:
            result[i] = 48 # '0'
        else:
            result[i] = 49 # '1'
    return bytes(result)

main()