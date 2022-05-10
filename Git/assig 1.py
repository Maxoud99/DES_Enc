import base64
import sys

# _pythonMajorVersion is used to handle Python2 and Python3 differences.
_pythonMajorVersion = sys.version_info[0]

# Modes of crypting / cyphering
ECB = 0
CBC = 1

# Modes of padding
PAD_NORMAL = 1
PAD_PKCS5 = 2

class des():

    # ---------------------------------------------------------------------
    # Permutation table DES
    Key_pc1 = [56, 48, 40, 32, 24, 16, 8,
               0, 57, 49, 41, 33, 25, 17,
               9, 1, 58, 50, 42, 34, 26,
               18, 10, 2, 59, 51, 43, 35,
               62, 54, 46, 38, 30, 22, 14,
               6, 61, 53, 45, 37, 29, 21,
               13, 5, 60, 52, 44, 36, 28,
               20, 12, 4, 27, 19, 11, 3
               ]
    # ---------------------------------------------------------------------
    # number left rotations of pc1
    rotate_left = [
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    ]
    # ---------------------------------------------------------------------
    # permuted choice key (table 2)
    key_pc2 = [
        13, 16, 10, 23, 0, 4,
        2, 27, 14, 5, 20, 9,
        22, 18, 11, 3, 25, 7,
        15, 6, 26, 19, 12, 1,
        40, 51, 30, 36, 46, 54,
        29, 39, 50, 44, 32, 47,
        43, 48, 38, 55, 33, 52,
        45, 41, 49, 35, 28, 31
    ]
    # ---------------------------------------------------------------------
    # initial permutation IP
    IP = [57, 49, 41, 33, 25, 17, 9, 1,
          59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5,
          63, 55, 47, 39, 31, 23, 15, 7,
          56, 48, 40, 32, 24, 16, 8, 0,
          58, 50, 42, 34, 26, 18, 10, 2,
          60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6
          ]
    # ---------------------------------------------------------------------
    # Expansion table for turning 32 bit blocks into 48 bits
    expansion_table = [
        31, 0, 1, 2, 3, 4,
        3, 4, 5, 6, 7, 8,
        7, 8, 9, 10, 11, 12,
        11, 12, 13, 14, 15, 16,
        15, 16, 17, 18, 19, 20,
        19, 20, 21, 22, 23, 24,
        23, 24, 25, 26, 27, 28,
        27, 28, 29, 30, 31, 0
    ]
    # ---------------------------------------------------------------------
    # The S-boxes
    S_boxes = [
        # S1
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
         0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
         4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
         15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],

        # S2
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
         3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
         0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
         13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],

        # S3
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
         13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
         13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
         1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],

        # S4
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
         13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
         10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
         3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],

        # S5
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
         14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
         4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
         11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],

        # S6
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
         10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
         9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
         4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],

        # S7
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
         13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
         1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
         6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],

        # S8
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
         1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
         7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
         2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ]
    # ---------------------------------------------------------------------
    # 32-bit permutation function P used on the output of the S-boxes
    P_32_S_boxes = [
        15, 6, 19, 20, 28, 11,
        27, 16, 0, 14, 22, 25,
        4, 17, 30, 9, 1, 7,
        23, 13, 31, 26, 2, 8,
        18, 12, 29, 5, 21, 10,
        3, 24
    ]
    # ---------------------------------------------------------------------
    # final permutation IP^-1
    IP_inverse = [
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25,
        32, 0, 40, 8, 48, 16, 56, 24
    ]
    # ---------------------------------------------------------------------
    # Type of crypting being done
    ENCRYPT = 0x00
    DECRYPT = 0x01

    # ---------------------------------------------------------------------
    # Initialisation (Constructor)
    def __init__(self, key, mode=ECB, IV=None, padmode=PAD_NORMAL):
        self.L_LeftSide = []
        self.R_RightSide = []
        if len(key) != 8:
            raise ValueError("The DES key size is incorrect. The length of the key must be exactly 8 bytes.")
        self.key_size = 8
        self.block_size = 8
        self.Kn = [[0] * 48] * 16  # 16 48-bit keys (K1 - K16)
        self.final = []
        self._mode = mode
        self._iv = IV
        self._padmode = padmode
        self.__key = key
        self.Generate16SubKeys()


    # ---------------------------------------------------------------------
    def String2Binary(self, data):
        l = len(data) * 8
        result = [0] * l
        pos = 0
        for ch in data:
            i = 7
            while i >= 0:
                if ch & (1 << i) != 0:
                    result[pos] = 1
                else:
                    result[pos] = 0
                pos += 1
                i -= 1

        return result

    # ---------------------------------------------------------------------
    def Binary2String(self, data):
        result = []
        pos = 0
        c = 0
        while pos < len(data):
            c += data[pos] << (7 - (pos % 8))
            if (pos % 8) == 7:
                result.append(c)
                c = 0
            pos += 1

        return bytes(result)

    # ---------------------------------------------------------------------
    def do_permutatation(self, table, block):
        """permute using the permutation table"""
        return list(map(lambda x: block[x], table))

    # ---------------------------------------------------------------------
    # Create the 16 round subkeys

    def Generate16SubKeys(self):
        """Create the 16 round subkeys"""
        key = self.do_permutatation(des.Key_pc1, self.String2Binary(self.__key))
        i = 0
        # Split into Left and Right sections
        self.L_LeftSide = key[:28]
        self.R_RightSide = key[28:]
        while i < 16:
            j = 0
            # Perform circular left shifts
            while j < des.rotate_left[i]:
                self.L_LeftSide.append(self.L_LeftSide[0])
                del self.L_LeftSide[0]

                self.R_RightSide.append(self.R_RightSide[0])
                del self.R_RightSide[0]

                j += 1

            # Create one of the 16 subkeys through pc2 permutation
            self.Kn[i] = self.do_permutatation(des.key_pc2, self.L_LeftSide + self.R_RightSide)

            i += 1

    # ---------------------------------------------------------------------
    def crypt_base_des(self, block, crypt_type):
        """DES bit manipulation is used to encrypt the data block."""
        block = self.do_permutatation(des.IP, block)
        self.L_LeftSide = block[:32]
        self.R_RightSide = block[32:]

        # Encryption
        if crypt_type == des.ENCRYPT:
            iteration = 0
            iteration_adjustment = 1
        # Decryption
        else:
            iteration = 15
            iteration_adjustment = -1

        i = 0
        # Repeat for 16 times
        while i < 16:
            # Make a copy of R[i-1], this will later become L[i]
            tempR = self.R_RightSide[:]

            # Permutate R[i - 1] to start creating R[i]
            self.R_RightSide = self.do_permutatation(des.expansion_table, self.R_RightSide)

            # Exclusive or R[i - 1] with K[i], create B[1] to B[8] whilst here
            self.R_RightSide = list(map(lambda x, y: x ^ y, self.R_RightSide, self.Kn[iteration]))
            B = [self.R_RightSide[:6], self.R_RightSide[6:12], self.R_RightSide[12:18], self.R_RightSide[18:24], self.R_RightSide[24:30], self.R_RightSide[30:36], self.R_RightSide[36:42],
                 self.R_RightSide[42:]]
            # Optimization: Replaced below commented code with above

            # Permutate B[1] to B[8] using the S-Boxes
            j = 0
            Bn = [0] * 32
            pos = 0
            while j < 8:
                # Work out the offsets
                m = (B[j][0] << 1) + B[j][5]
                n = (B[j][1] << 3) + (B[j][2] << 2) + (B[j][3] << 1) + B[j][4]

                # Find the permutation value
                v = des.S_boxes[j][(m << 4) + n]

                # Turn value into bits, add it to result: Bn
                Bn[pos] = (v & 8) >> 3
                Bn[pos + 1] = (v & 4) >> 2
                Bn[pos + 2] = (v & 2) >> 1
                Bn[pos + 3] = v & 1

                pos += 4
                j += 1

            # Permutate the concatination of B[1] to B[8] (Bn)
            self.R_RightSide = self.do_permutatation(des.P_32_S_boxes, Bn)

            # Xor with L[i - 1]
            self.R_RightSide = list(map(lambda x, y: x ^ y, self.R_RightSide, self.L_LeftSide))
            self.L_LeftSide = tempR

            i += 1
            iteration += iteration_adjustment

        # Final permutation of R[16]L[16]
        self.final = self.do_permutatation(des.IP_inverse, self.R_RightSide + self.L_LeftSide)
        return self.final

    # ---------------------------------------------------------------------
    def Pading(self, data, pad, padmode):
        # Pad data if not multiple of 8 bytes
        if padmode is None:
            # Get the default padding mode.
            padmode = self._padmode
        if pad and padmode == PAD_PKCS5:
            raise ValueError("Cannot use a pad character with PAD_PKCS5")

        if padmode == PAD_NORMAL:
            if len(data) % self.block_size == 0:
                # No padding required.
                return data

            if not pad:
                # Get the default padding.
                pad = self.getPadding()
            if not pad:
                raise ValueError("Data must be a multiple of " + str(
                    self.block_size) + " bytes in length. Use padmode=PAD_PKCS5 or set the pad character.")
            data += (self.block_size - (len(data) % self.block_size)) * pad

        elif padmode == PAD_PKCS5:
            pad_len = 8 - (len(data) % self.block_size)

            data += bytes([pad_len] * pad_len)

        return data

    # ---------------------------------------------------------------------
    def Unpadding(self, data, pad, padmode):
        if not data:
            return data
        if pad and padmode == PAD_PKCS5:
            raise ValueError("Cannot use a pad character with PAD_PKCS5")
        if padmode is None:
            # Get the default padding mode.
            padmode = self._padmode

        if padmode == PAD_NORMAL:
            if not pad:
                # Get the default padding.
                pad = self.getPadding()
            if pad:
                data = data[:-self.block_size] + \
                       data[-self.block_size:].rstrip(pad)

        elif padmode == PAD_PKCS5:

            pad_len = data[-1]
            data = data[:-pad_len]

        return data

    # ---------------------------------------------------------------------

    def crypt(self, data, crypt_type):
        """Crypt the data in blocks, running it through des_crypt()"""

        # Error check the data
        if not data:
            return ''
        if len(data) % self.block_size != 0:
            if crypt_type == des.DECRYPT:  # Decryption must work on 8 byte blocks
                raise ValueError(
                    "Invalid data length, data must be a multiple of " + str(self.block_size) + " bytes\n.")
            if not self.getPadding():
                raise ValueError("Invalid data length, data must be a multiple of " + str(
                    self.block_size) + " bytes\n. Try setting the optional padding character")
            else:
                data += (self.block_size - (len(data) % self.block_size)) * self.getPadding()

        if self._mode == CBC:
            if self._iv:
                iv = self.String2Binary(self._iv)
            else:
                raise ValueError("For CBC mode, you must supply the Initial Value (IV) for ciphering")

        # Split the data into blocks, crypting each one seperately
        i = 0
        result = []
        while i < len(data):
            block = self.String2Binary(data[i:i + 8])

            # Xor with IV if using CBC mode
            if self._mode == CBC:
                if crypt_type == des.ENCRYPT:
                    block = list(map(lambda x, y: x ^ y, block, iv))

                processed_block = self.crypt_base_des(block, crypt_type)

                if crypt_type == des.DECRYPT:
                    processed_block = list(map(lambda x, y: x ^ y, processed_block, iv))
                    iv = block
                else:
                    iv = processed_block
            else:
                processed_block = self.crypt_base_des(block, crypt_type)

            result.append(self.Binary2String(processed_block))
            i += 8


        return bytes.fromhex('').join(result)

    # ---------------------------------------------------------------------
    def encrypt(self, data, pad=None, padmode=None):
        data = self.Pading(data, pad, padmode)
        return self.crypt(data, des.ENCRYPT)

    # ---------------------------------------------------------------------
    def decrypt(self, data, pad=None, padmode=None):
        data = self.crypt(data, des.DECRYPT)
        return self.Unpadding(data, pad, padmode)


# ---------------------------------------------------------------------

'''
Now let us test our class with some data (plain text and Key)
and later compare the output with openssl output and check
is it the same result or not.
'''

# -------------------------------------------------------------
data = b"Real Madrid is the best club in the world"
key = bytes.fromhex('524f445259474f53')
k = des(key, ECB, padmode=PAD_PKCS5)
d = k.encrypt(data)
print(f'Plain Text:  {data}')
print("Encrypted Hex: %r" % d.hex())
print("Encrypted Bytes: %r" % d)
print("Encrypted Base64: %r" % base64.b64encode(d))
print("Decrypted: %r" % k.decrypt(d))
assert k.decrypt(d, padmode=PAD_PKCS5) == data  # data must be in Bytes
# -----------------------------------------------------------------
data = b"Real Madrid is the best club in the world"
key = bytes.fromhex('524f445259474f53')
IV = bytes.fromhex('0000000000000000')
k = des(key, CBC, IV, padmode=PAD_PKCS5)
d = k.encrypt(data)
print(f'Plain Text:  {data}')
print("Encrypted Hex: %r" % d.hex())
print("Encrypted Bytes: %r" % d)
print("Encrypted Base64: %r" % base64.b64encode(d))
print("Decrypted: %r" % k.decrypt(d))
assert k.decrypt(d, padmode=PAD_PKCS5) == data
# ---------------------------------------------------------------------
'''
We did find that both outputs from ECB and CBC match the output from the openssl.
This implies that our code is working on the proper way.
--------------------------------------------------------------------------------
Team names:
Abdelrahman Gelany 43-17100.
Mohamed Abdelmaksoud 43-16710.
Mohamed Diaa 43-12821.
'''
