from ciphers import simon
from utils import util


def checks(start, end, key, input_diff, output_diff, rounds, offset, counter, version=32):
    data_list = util.generate_test_data(start, end, input_diff)
    count = 0
    res = 0
    cipher = simon.SimonCipher(
            block_size=32, key_size=64, key=key, rounds=rounds, offset=offset
        )
    for x1 in data_list:
        count += 1
        if count == 10000:
            counter.value += count
            count = 0
        x2 = x1 ^ input_diff
        c1 = cipher.encrypt(x1)
        c2 = cipher.encrypt(x2)
        c3 = c1 ^ output_diff
        c4 = c2 ^ output_diff
        x3 = cipher.decrypt(c3)
        x4 = cipher.decrypt(c4)
        if x3 ^ x4 == input_diff:
            res += 1
    counter.value += count
    return res

