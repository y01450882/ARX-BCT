import numpy as np
from collections import deque

IR = (
    1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1,
    0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0,
    1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0,
    0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1,
    0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1,
    1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1,
    0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0,
    1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1,
    1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1,
    1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1,
    0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1,
    1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0,
    0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1,
    0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1,
    1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0,
)


def num2bits_cpu(num, bit_length):
    bits = []
    for i in range(bit_length):
        bits.append(num & 1)
        num >>= 1
    return bits


def lfsr(iv):
    state = num2bits_cpu(iv, 80)
    for i in range(254 * 2):
        yield state[0]
        state.append(state[0] ^ state[19] ^ state[30] ^ state[67])
        state.pop(0)


def generate_round_key(key):
    keys = np.zeros(254 * 2, dtype=np.int32)
    stream = lfsr(key)
    for i in range(254 * 2):
        keys[i] = next(stream)
    return keys


def generate_round_key_simon(key, key_size, word_size, rounds, zseq):
    mod_mask = (2 ** word_size) - 1
    m = key_size // word_size
    key_schedule = []
    k_init = [((key >> (word_size * ((m - 1) - x))) & mod_mask) for x in range(m)]
    k_reg = deque(k_init)
    round_constant = mod_mask ^ 3
    for x in range(rounds):
        rs_3 = ((k_reg[0] << (word_size - 3)) + (k_reg[0] >> 3)) & mod_mask
        if m == 4:
            rs_3 = rs_3 ^ k_reg[2]
        rs_1 = ((rs_3 << (word_size - 1)) + (rs_3 >> 1)) & mod_mask
        c_z = ((zseq >> (x % 62)) & 1) ^ round_constant
        new_k = c_z ^ rs_1 ^ rs_3 ^ k_reg[m - 1]
        key_schedule.append(k_reg.pop())
        k_reg.appendleft(new_k)
    return key_schedule


def compute_hamming(ns):
    count = 0
    if type(ns) == int:
        ns = num2bits_cpu(ns, 16)
    for n in ns:
        if n == 1:
            count += 1
        elif n > 1:
            bits = num2bits_cpu(n, 100)
            for b in bits:
                if b == 1:
                    count += 1
    return count


def hmd4int(x, y):
    """整数的汉明距离"""
    z = x ^ y
    count = 0
    while z != 0:
        if z & 1 == 1:
            count += 1
        z = z >> 1
    return count


z0 = 0b01100111000011010100100010111110110011100001101010010001011111


def d1(n):
    hamming_res = []
    keys = generate_round_key_simon(n, 64, 16, 32, z0)
    for key in keys:
        hamming = compute_hamming(key)
        hamming_res.append(hamming)
    return hamming_res


yes = [0xaf13897e, ]  # 0x61bf3e29, 0x81665e65, 0x36d46a94, 0xbbaa99fd, 0x1394e648, 0xb4c3b80a, 0x4fde0257]
no = [0x61bf3e29, ]  # 0x49ca9a86, 0x4517a572]


def compute_ir(ns):
    for i in range(len(IR)):
        ns[i * 2] = IR[i]


def dafdsaf():
    a = 0x99e349f
    ass = generate_round_key(a)
    b = 0x4c0ae9a6
    bss = generate_round_key(b)
    c = 0x2e9a9dca
    css = generate_round_key(c)
    compute_ir(ass)
    compute_ir(bss)
    compute_ir(css)
    print(compute_hamming(ass))
    print(compute_hamming(bss))
    print(compute_hamming(css))


dafdsaf()
