import os

def makedirs(dirs:list):
    for dir in dirs:
        if not os.path.exists(dir):
            os.makedirs(dir)