# Manually input each pair of ciphertexts to get m1 xor m2 
# (exclusive OR of the plaintexts)

# Input the pair of hexadecimal ciphertexts
hex1 = ""  
hex2 = ""  

# convert the hexadecimal numbers to integers
int1 = int(hex1, 16)
int2 = int(hex2, 16)

# XOR the two integers
result = int1 ^ int2

# convert the result back to a hexadecimal string
hex_result = hex(result)

# print the result. m1 xor m2
print(hex_result)
