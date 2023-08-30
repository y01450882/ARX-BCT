import time

def print_process(counter, total):
    while True:
        print("\rProcessing: {0}/{1}".format(counter.value, total), end="")
        time.sleep(2)
    