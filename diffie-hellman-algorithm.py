from __future__ import print_function
 
# Mutually agreed modulo and base
p = 23 
g = 5 # primitive root modulo 23
 
KR_a = 6
KR_b = 15
 
# Initiate Key Exchange
print("Publicly Shared Variables between P1 and P2>>")
print("")
print("Shared Prime: " , p)
print("Shared Base:  " , g)
print("") 
# A = g^a mod p
A = (g**KR_a) % p
print("P1 Sends Over Public Channel: " , A)
# B = g^b mod p
B = (g**KR_b) % p
print("P2 Sends Over Public Channel: ", B)
print("") 
print("Privately Calculated Shared Secret>>")
print("")
# P1 Computes Shared Secret: s = B^a mod p
K_a = (B ** KR_a) % p
print("P1 Shared Secret: ", K_a)
# P2 Computes Shared Secret: s = A^b mod p
K_b = (A ** KR_b) % p
print("P2 Shared Secret: ", K_b)
