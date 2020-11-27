import numpy as np


sbox = [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2]  # my sbox

bits = 4    # number of bits of input to sbox
size = 2**bits

# linear approximation table
LAT = np.zeros((size, size)).astype(int)

for alpha in range(size):
    for beta in range(size):

        equal = 0  # incremented when alpha.m == beta.S[m]

        # iterating through all plaintexts
        for m in range(2**bits):

            mask_alpha_m = bin(alpha & m).count('1') % 2    # alpha.m
            mask_beta_c = bin(beta & sbox[m]).count('1') % 2    # beta.S[m]

            # check when they are equal
            if mask_alpha_m == mask_beta_c:
                equal += 1

        LAT[alpha][beta] = equal - 8  # updating LAT

LAT = np.delete(LAT, 0, axis=0)  # dropping 1st row i.e. alpha = 0
LAT = np.delete(LAT, 0, axis=1)  # dropping 1st column i.e. beta = 0

print(LAT)
