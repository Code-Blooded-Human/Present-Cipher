import random
import os
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

    possibleAfterSbox = []
    possibleCipherText = []

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
        if(len(message)*8 > 64):  # verify that size of is less than 64 bits
            print("Length of message must be 64 bits")
            exit()

        # applying padding if needed
        padCount = 0
        if (len(message) % 8):
            padCount = 8 - (len(message) % 8)
        message += chr(padCount)*padCount
        self.m = int.from_bytes(message.encode(), byteorder='big')  # convert self.m string to integer
    def setMessageInt(self, int_message):
        self.m = int_message
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

    def reverseSbox(self,nibble):
        i = 0
        while self.sbox[i] != nibble :
            i = i+1
        return i



    def encryption(self):
        state = self.m
        for i in range(self.rounds-1):
            state = self.addRoundKey(state, self.subkeys[i])
            state = self.sBoxLayer(state)
            state = self.pLayer(state)
        # last round
        state = self.addRoundKey(state, self.subkeys[-1])

        # convert number of hex string
        return hex(state).replace('0x', '')
    
    def threeRoundEncrypt(self,message):
        state = message
        for i in range(0,2):
            state = self.addRoundKey(state, self.subkeys[i])
            state = self.sBoxLayer(state)
            state = self.pLayer(state)
        #third
        state = self.addRoundKey(state, self.subkeys[2])
        return state
    
    
   
    
    

    def message_generation(self, exp, diff):
        self.filtering()
        count = 2**exp
        k = 0
        for i in range(0,count):
            m1 = i
            m2 = i^diff
            c1 = self.threeRoundEncrypt(m1)
            c2 = self.threeRoundEncrypt(m2)
            for j in range(0, len(self.possibleAfterSbox)):
                if self.possibleAfterSbox[j] == c1 ^ c2:
                    #print(c1, c2)
                    self.possibleCipherText.append(m1)
                    k = k+1
                    break
        print("Filtered: ", k, " Pairs")

    def key_guess(self, diff):
        print("Possible Keys")
        for i in range(0,64):
            a = i>>0 & 1
            b = i>>1 & 1
            c = i>>2 & 1
            d = i>>3 & 1
            p = i>>4 & 1
            q = i>>5 & 1
            r = i>>6 & 1
            s = i>>7 & 1
            key_guess = f"0x0{s}0{d}0{r}0{c}0{q}0{b}0{p}0{a}"
            key_guess_int = int(key_guess,16)
            counter = 0
            for j in range(0, len(self.possibleCipherText)):
                m1 = self.possibleCipherText[j]
                m2 = m1 ^ diff
                c1 = self.threeRoundEncrypt(m1)
                c2 = self.threeRoundEncrypt(m2)
                c1_prime = c1^key_guess_int
                c2_prime = c2^key_guess_int
              
                s0_c1 = ((c1_prime>>(12*4) &1)*8) + ((c1_prime>>(8*4)&1)*4) +((c1_prime>>(4*4) &1)*2) + (c1_prime>>(0*4)&1)
                s0_c2 = ((c2_prime>>(12*4) &1)*8) + ((c2_prime>>(8*4)&1)*4) +((c2_prime>>(4*4) &1)*2) + (c2_prime>>(0*4)&1)
                s8_c1 = ((c1_prime>>(14*4) &1)*8) + ((c1_prime>>(10*4)&1)*4) +((c1_prime>>(4*6) &1)*2) + (c1_prime>>(2*4)&1)
                s8_c2 = ((c2_prime>>(14*4) &1)*8) + ((c2_prime>>(10*4)&1)*4) +((c2_prime>>(4*6) &1)*2) + (c2_prime>>(2*4)&1)
                
                s0_c1_invr = self.reverseSbox(s0_c1)
                s0_c2_invr = self.reverseSbox(s0_c2)
                s8_c1_invr = self.reverseSbox(s8_c1)
                s8_c2_invr = self.reverseSbox(s8_c2)
                
                if s0_c1_invr^s0_c2_invr == 9 and s8_c1_invr^s8_c2_invr == 9:
                    counter = counter+1
            
            
            
            if counter >= 1024 :
                print(key_guess, counter/2**18) 
        print("Actual Subkey for last round: ", hex(self.subkeys[2]))
        

    def filtering(self):
        afterSbox = ['2', '4', '6', '8' , 'c', 'e']
        k=1
        for i in range(0,6):
            for j in range(0,6):
                str = '0x0000000'+afterSbox[i]+'0000000'+afterSbox[j]
                af = int(str,16)
                pl = self.pLayer(af)
                self.possibleAfterSbox.append(pl)
                k = k+1


def main():
    cipher = Present()
    key = os.urandom(10)
    print("Master Key ->",key.hex())
    cipher.setKey(key.hex())
    cipher.message_generation(18,16388)
    cipher.key_guess(16388)
main()