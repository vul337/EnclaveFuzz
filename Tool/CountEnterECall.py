#!/usr/bin/python3
import argparse
import os
import re

gECallCnt = {}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('logs', nargs="+", metavar="<xxx.log>")
    args = parser.parse_args()

    logs = args.logs
    for log in logs:
        log_abs = os.path.abspath(log)
        if os.path.exists(log_abs):
            print("== Process "+log+" ==")
            with open(log_abs) as log_file:
                lines = log_file.readlines()
                for line in lines:
                    match = re.search(r"Enter\s+(\w+)", line)
                    if match:
                        ECallName = match.group(1)
                        if ECallName in gECallCnt.keys():
                            gECallCnt[ECallName] += 1
                        else:
                            gECallCnt[ECallName] = 1
            for ECallName in gECallCnt.keys():
                print(str(gECallCnt[ECallName])+" Enter "+ECallName)


if __name__ == "__main__":
    main()
