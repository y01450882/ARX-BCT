import os


def generate_test_data(start, end, in_diff):
    records = set()
    for i in range(start, end):
        x1 = i
        if x1 in records:
            continue
        if x1 > (x1 ^ in_diff):
            continue
        records.add(x1)
    return list(records)


def print_info(str):
    pid = os.getpid()
    print("Process ID:{0}, Msg: {1}".format(pid, str))


def split_task(start, end, core_num):
    batch_task_num = core_num * core_num
    batch_size = int((end - start) / batch_task_num)
    seg_list = list()
    seg_list.append(0)
    for _ in range(batch_task_num):
        start = seg_list[-1]
        seg_list.append(start + batch_size)
    if seg_list[-1] != end:
        seg_list.append(end)
    return seg_list


