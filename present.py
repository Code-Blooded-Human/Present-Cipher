from binascii import hexlify
class Present():
    '''
    key (hex str): Key used for encryption. The length of key string must be 20\n
    message (str): Plaintext to encrypt. The length of message must be less or equal to 8
    '''
    sbox = [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2]  # sbox
    permute = [0]*64  # permutation layer

    subkeys = []
    rounds = 32  # 31 rounds in present cipher

    masterKey = 0  # 80/128 bit key # hexadecimal string
    m = 0  # 64 bit message

    def __init__(self):
        self.initPLayer()

    def setKey(self, key):
        if(len(key)*4 == 80 or len(key)*4 == 128):  # verify that size of key is 80 bits
            temp_key = bytes.fromhex(key)  # convert key from hex to bytes
            self.masterKey = int.from_bytes(temp_key, byteorder='big')  # convert bytes to integer
            if((len(key)*4) == 80):
                self.subKeys80()  # generate subkeys using 80 bit masterKey
            else:
                self.subKeys128()
        else:
            print('Length of key must be either 80 bits or 128 bits')
            exit()

    def setMessage(self, message):
        self.m = int(message, 16)

    # permutation layer is initialized
    def initPLayer(self):
        c = -1
        for i in range(64):
            if ((16*i) % 64) == 0:
                c += 1
            self.permute[i] = (16*i) % 64 + c

    def subKeys80(self):
        for i in range(1, self.rounds+1):  # for each round
            self.subkeys.append(self.masterKey >> 16)  # last 64 bits of masterKey is used as subkey

            # rotate the masterKey by 61 positions to left
            self.masterKey = ((self.masterKey & (2**19 - 1)) << 61) | (self.masterKey >> 19)

            # pass the leftmost 4 bits to sbox and update masterKey
            self.masterKey = ((self.sbox[self.masterKey >> 76] << 76) | self.masterKey & (2**76 - 1))

            # xor k[19],k[18],k[17],k[16],k[15] with round counter and update masterKey
            self.masterKey = (self.masterKey ^ (i << 15))

    def subKeys128(self):
        for i in range(1, self.rounds+1):  # for each round
            self.subkeys.append(self.masterKey >> 64)  # last 64 bits of masterKey is used as subkey

            # rotate the masterKey by 61 positions to left
            self.masterKey = (((self.masterKey & (2**67 - 1)) << 61) | (self.masterKey >> 67))

            # pass the leftmost 8 bits to sbox and update masterKey
            out1 = (self.sbox[self.masterKey >> 124] << 124)  # sbox of bits from 124 to 127
            out2 = (self.sbox[(self.masterKey >> 120) & 15] << 120)  # sbox of bits from 120 to 123
            out3 = (self.masterKey & (2**120 - 1))  # first 120 bits of masterkey
            self.masterKey = (out1 | out2 | out3)

            # xor k[66],k[65],k[64],k[63],k[62] with round counter and update masterKey
            self.masterKey = (self.masterKey ^ (i << 62))

    def pLayer(self, state):
        res = 0
        for i in range(64):  # for each bit of the state
            bit = ((state >> i) & 1)  # get the ith bit
            res = (res | (bit << self.permute[i]))
        return res

    def addRoundKey(self, state, subkey):
        return (state ^ subkey)

    def sBoxLayer(self, state):
        res = 0
        for i in range(16):  # 4 bits at a time of the state
            bits = ((state >> (i*4)) & (2**4 - 1))
            res += (self.sbox[bits] << (i*4))
        return res

    def encryption(self):
        state = self.m
        for i in range(self.rounds-1):
            state = self.addRoundKey(state, self.subkeys[i])
            state = self.sBoxLayer(state)
            state = self.pLayer(state)
        # last round
        state = self.addRoundKey(state, self.subkeys[-1])

        # convert number of hex stringH
        return hex(state).replace('0x', '')

def main():
    print("Enter 8 Characters")
    msg_str = input()
    print("Enter key in hex, 20 hex characters for 80bit  or 32 hex characters for 128bit")
    key_hex_str = input()
    msg_hex = hexlify(msg_str.encode()).decode()
    cipher = Present()
    cipher.setKey(key_hex_str)
    cipher.setMessage(msg_hex)
    print("Encryption: ", cipher.encryption())

main()
