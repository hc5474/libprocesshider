#!/usr/bin/python3
import time

def stay_visible():
    print("Process is running...")
    while True:
        time.sleep(60)

stay_visible()
