
# Sbox shown in the answer script is used to find DDT
Sbox = [
    [0, 12],
    [1, 5],
    [2, 6],
    [3, 11],
    [4, 9],
    [5, 0],
    [6, 10],
    [7, 13],
    [8, 3],
    [9, 14],
    [10, 15],
    [11, 8],
    [12, 4],
    [13, 7],
    [14, 1],
    [15, 2]
]

DDT = []  # Differnce Distribution Table (list of lists)
bits = 4  # Number of Bits in Input
input_diff = list(range(2**bits))  # Input Difference (0 to 2^bits)

freq = {}  # stores the frequency of a number for a row in DDT

for i in input_diff:
    freq.clear()

    # u0 and u1 are inputs to Sbox
    for u0 in range(2**bits):

        # considering u0 xor u1 = i
        u1 = u0 ^ i

        # v0 = S(u0)
        v0 = Sbox[u0][1]

        # v1 = S(u1)
        v1 = Sbox[u1][1]

        # y = v0 xor v1
        y = v0 ^ v1

        # if y is present in freq then increment the counter
        if(y in freq.keys()):
            freq[y] += 1

        # otherwise create y
        else:
            freq[y] = 1

    # a row of DDT which shows the frequency of outputs for given inputs
    DDT.append([freq[i] if(i in freq.keys()) else 0 for i in range(2**bits)])

# displaying the DDT
for d in DDT:
    print('  '.join([str(x) if(x) else '-' for x in d]))

