from ciphers import katan
import utils.util as util


def checks(start, end, key, input_diff, output_diff, rounds, offset,counter, version=32):
    data_list = util.generate_test_data(start, end, input_diff)
    count = 0
    res = 0
    cipher = katan.KATAN(master_key=key, version=version)
    for x1 in data_list:
        count += 1
        if count == 10000:
            counter.value += count
            count = 0
        x2 = x1 ^ input_diff
        c1 = cipher.enc(plaintext=x1, from_round=offset, to_round=rounds)
        c2 = cipher.enc(plaintext=x2, from_round=offset, to_round=rounds)
        c3 = c1 ^ output_diff
        c4 = c2 ^ output_diff
        x3 = cipher.dec(ciphertext=c3, from_round=rounds, to_round=offset)
        x4 = cipher.dec(ciphertext=c4, from_round=rounds, to_round=offset)
        if x3 ^ x4 == input_diff:
            res += 1
    counter.value += count
    return res