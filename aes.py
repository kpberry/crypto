import time


def cipher(inp, expanded_key):
    # fill initial state value with data from the text
    state = [[None] * 4 for i in range(4)]
    for i in range(16):
        state[i % 4][int(i / 4)] = inp[i]

    # get the initial round key
    add_round_key(state, expanded_key, 0)

    # mix up the state real good
    for round in range(1, 14):
        # confusion: apply a transformation to screw up algebraic
        # attacks and destroy patterns
        sub_bytes(state)
        # diffusion - make sure that small changes in the
        # input result in large changes in the output
        shift_rows(state)
        mix_columns(state)
        # more confusion: continue to destroy patterns
        add_round_key(state, expanded_key, round)

    shift_rows(state)
    mix_columns(state)
    add_round_key(state, expanded_key, 14)

    output = [None] * 16
    for i in range(16):
        output[i] = state[i % 4][int(i / 4)]

    return output


def sub_bytes(state):
    for r in range(4):
        for c in range(4):
            # use the value in the state as an index
            # into the fancy-ass lookup table below
            index = state[r][c]
            state[r][c] = s_box[index]


def shift_rows(state):
    '''
    Diffuse the row information in the cipher by shifting the rows over

    |1  2  3  4 |    |1  2  3  4 |
    |5  6  7  8 | -> |6  7  8  5 |
    |9  10 11 12| -> |11 12 9  10|
    |13 14 15 16|    |16 13 14 15|
    '''
    for i in range(1, 4):
        state[i][0], state[i][1], state[i][2], state[i][3] \
            = state[i][i % 4], state[i][(i + 1) % 4], state[i][(i + 2) % 4], state[i][(i + 3) % 4]


def mix_columns(state):
    '''
    More diffusion; diffuse the column and row information in the cipher
    by performing a multiplication with the matrix

    |2 3 1 1|
    |1 2 3 1|
    |1 1 2 3|
    |3 1 1 2|

    in GF(2^8), meaning that additions are really XORs
    '''
    for c in range(4):
        a = [state[i][c] for i in range(4)]
        b = [((state[i][c] << 1) ^ 0x011b) & 0xff
             if state[i][c] & 0x80 else (state[i][c] << 1) & 0xff for i in range(4)]
        # this is the actual matrix multiplication part
        state[0][c] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3]
        state[1][c] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3]
        state[2][c] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3]
        state[3][c] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3]


def add_round_key(state, expanded_key, round):
    # XOR each of the bytes of the state with an element from the key schedule
    for r in range(4):
        for c in range(4):
            state[r][c] ^= expanded_key[round * 4 + c][r]


s_box = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
         0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
         0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
         0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
         0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
         0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
         0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
         0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
         0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
         0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
         0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
         0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
         0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
         0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
         0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
         0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]


def compute_rcon(i):
    c = 1
    if i == 0:
        return 0
    while i != 1:
        b = c & 0x80
        c <<= 1
        if b == 0x80:
            c ^= 0x1b
        i -= 1
    return c


rcon = list(map(compute_rcon, range(256)))


# uses a 256 bit key
def expand_key(key):
    # initialize the first bytes to the key
    result = [j for j in key]
    i = 1
    while len(result) < 240:
        t = result[-4:]
        if len(result) % 32 == 0:
            t = [s_box[j] for j in [t[1], t[2], t[3], t[0]]]
            t[0] ^= rcon[i]
            i += 1
        if len(result) % 32 == 16:
            t = [s_box[j] for j in t]

        for j in range(4):
            result.append(result[-32] ^ t[j])
    result = [result[j * 4:(j + 1) * 4] for j in range(60)]
    return result


def encrypt(text, key):
    bytes = [ord(i) for i in text]
    bytes.extend([0] * (16 - len(text) % 16))
    assert len(bytes) % 16 == 0
    expanded_key = expand_key(key)

    nonce = int(time.time()) * 2
    for i in range(int(len(bytes) / 16)):
        c = cipher(int_key_to_n_char_arr(nonce ^ i, 16), expanded_key)
        for j in range(16):
            bytes[j + i * 16] ^= c[j]
    return [nonce] + bytes


def decrypt(text, key):
    nonce = text[0]
    text = text[1:]
    assert len(text) % 16 == 0
    expanded_key = expand_key(key)

    for i in range(int(len(text) / 16)):
        q = int_key_to_n_char_arr(nonce ^ i, 16)
        c = cipher(q, expanded_key)
        for j in range(16):
            text[j + i * 16] ^= c[j]
    return ''.join(map(chr, text[:text.index(0)]))


def int_key_to_n_char_arr(key, n=32):
    return [(key >> i * 8) & 0xff for i in range(n - 1, -1, -1)]
