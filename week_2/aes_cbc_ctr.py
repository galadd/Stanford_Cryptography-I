"""
In this project you will implement two encryption/decryption systems, 
one using AES in CBC mode and another using AES in counter mode (CTR).  

In both cases the 16-byte encryption IV is chosen at random and is prepended to the ciphertext.

For CBC encryption we use the PKCS5 padding scheme discussed  
in the lecture (14:04). While we ask that you implement both encryption and decryption, 
we will only test the decryption function.   

In the following questions you are given an AES key 
and a ciphertext (both are  hex encoded ) and your goal is to recover the plaintext 
and enter it in the input boxes provided below.

Question 1
CBC key: 140b41b22a29beb4061bda66b6747e14
CBC Ciphertext 1: 4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81

Question 2
CBC key: 140b41b22a29beb4061bda66b6747e14
CBC Ciphertext 2: 5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253

Question 3
CTR key: 36f18357be4dbd77f050515c73fcf9f2
CTR Ciphertext 1: 69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329

Question 4
CTR key: 36f18357be4dbd77f050515c73fcf9f2
CTR Ciphertext 2: 770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451
"""

from Crypto.Cipher import AES
from Crypto.Util import Counter

def main():
	blockSize = 16 # 16-byte encryption
	pt1 = cbc_decrypt("140b41b22a29beb4061bda66b6747e14", "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81", blockSize)	
	pt2 = cbc_decrypt("140b41b22a29beb4061bda66b6747e14", "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253", blockSize)	
	pt3 = ctr_decrypt("36f18357be4dbd77f050515c73fcf9f2", "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329", blockSize)	
	pt4 = ctr_decrypt("36f18357be4dbd77f050515c73fcf9f2", "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451", blockSize)	
        
	print(pt1)
	print(pt2)
	print(pt3)
	print(pt4)

def cbc_decrypt(key, ciphertext, block_size):
    # Divide cypherText into blocks of size blockSize*2
    cypherTextBlocks = [ciphertext[i:i+(block_size*2)] for i in range(0, len(ciphertext), (block_size*2))]
    
    # Convert each block from hex to bytes
    cypherTextBlocksDecoded = [bytes.fromhex(block) for block in cypherTextBlocks]
    
    # Extract the key from its hex representation
    k = bytes.fromhex(key)
    pt = b""
    
    # Decrypt each block using AES-ECB and XOR it with the previous block
    for i in range(len(cypherTextBlocksDecoded) - 1, 0, -1):
        # Decrypt the current block using AES-ECB
        cipher = AES.new(k, AES.MODE_ECB).decrypt(cypherTextBlocksDecoded[i])
        
        # XOR the decrypted block with the previous block
        plaintext = bytes([a ^ b for a, b in zip(cipher, cypherTextBlocksDecoded[i-1])])
        
        # Add the resulting plaintext to the beginning of the final plaintext
        pt = plaintext + pt
    
    # Remove padding from plaintext
    paddingAmount = pt[-1]
    pt = pt[:-paddingAmount]
    
    # Return the plaintext as a UTF-8 string
    return pt.decode('utf-8')

def ctr_decrypt(key, ciphertext, block_size):
    # Convert the key and ciphertext from hexadecimal strings to bytes objects
    key_bytes = bytes.fromhex(key)
    ciphertext_bytes = bytes.fromhex(ciphertext)
    
    # Get the initialization vector (IV) from the ciphertext
    iv = ciphertext_bytes[:block_size]
    
    # Get the ciphertext without the IV
    ciphertext_without_iv = ciphertext_bytes[block_size:]
    
    # Create a counter with the initial value set to the IV
    ctr = Counter.new(block_size * 8, initial_value=int.from_bytes(iv, byteorder='big'))
    
    # Create an AES cipher object in CTR mode with the given key and counter
    cipher = AES.new(key_bytes, AES.MODE_CTR, counter=ctr)
    
    # Decrypt the ciphertext without the IV using the AES cipher in CTR mode
    padded_plaintext = cipher.decrypt(ciphertext_without_iv)
    
    # Return the padded plaintext
    return padded_plaintext


main()