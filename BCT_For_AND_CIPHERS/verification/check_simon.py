import random
import math
import multiprocessing
from task import task_simon
from utils import util
from task import task_counter

MAX_PROCESSES = 11

POOL = multiprocessing.get_context('fork').Pool(processes=MAX_PROCESSES)
ROUNDS = 15
WEIGHT = 22
CIPHER_NAME = "SIMON32"

def verify(in_diff, out_diff, rounds, counter, offset=0):
    counter.value = 0
    test_n = 2**WEIGHT
    print("\n{}, INPUT_DIFF:{}, OUTPUT_DIFF:{}, the number of test data: {}".format(CIPHER_NAME, hex(in_diff), hex(out_diff), test_n))
    key = random.randint(0, 2**32)
    result = 0
    task_list = []
    seg_list = util.split_task(0, test_n, MAX_PROCESSES)
    for i in range(len(seg_list)-1):  
        task_list.append(
            POOL.apply_async(
                task_simon.checks,
                args=(
                    seg_list[i],
                    seg_list[i+1],
                    key,
                    in_diff,
                    out_diff,
                    rounds, 
                    offset,
                    counter
                ),
            )
        )
    for task in task_list:
        result += task.get()
    if result == 0:
        print("\nCipher: {0}, Invalid".format(CIPHER_NAME))
        return "Invalid"
    prob = result/test_n
    final_weight = math.log2(prob)
    print("\nCipher:{0}, prob:{1}, weight:{2}".format(CIPHER_NAME, prob, final_weight))
    return str(final_weight)


if __name__ == "__main__":
    result_file_name = 'verify_result_simon32-{0}.txt'.format(ROUNDS)
    manager = multiprocessing.Manager()
    counter = manager.Value('i', 0)
    counter_task = POOL.apply_async(
                task_counter.print_process,
                args=(
                    counter,
                    2**WEIGHT
                ),
            )
    save_file = open(result_file_name, "w")
    data_file = open("diff_files/check_list_simon32.txt", "r")
    data_list = []
    data = data_file.readline()


    while data != "":
        temps = data.split(",")
        data = []
        for i in temps:
            if i.startswith("0x"):
                data.append(int(i, 16))
            else:
                data.append(int(i))
        data.append(1)
        data_list.append(data)
        data = data_file.readline()


    for dd in data_list:
        res = verify(dd[0], dd[3], ROUNDS, counter)
        save_str = "CIPHER:{0}, INPUT_DIFF:{1}, OUTPUT_DIFF:{2}\n\t WEIGHT:{3}\n".format(CIPHER_NAME, dd[0], dd[3], res)
        save_file.write(save_str)


