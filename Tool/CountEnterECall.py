#!/usr/bin/python3
import argparse
import os
import re
from tqdm.auto import tqdm

gECallCnt = {}


def main():
    parser = argparse.ArgumentParser(
        description="Analyse all *.log in <log_dir> to count Enter ECall_XXX")
    parser.add_argument('log_dir')
    parser.add_argument('--kind', default="Enter")
    args = parser.parse_args()

    for log in tqdm(os.listdir(args.log_dir)):
        if not log.endswith(r".log"):
            continue
        log_abs = os.path.join(args.log_dir, log)
        if os.path.exists(log_abs):
            with open(log_abs, errors="backslashreplace") as log_file:
                lines = log_file.readlines()
                for line in lines:
                    match = re.search(args.kind+r"\s+(\w+)", line)
                    if match:
                        ECallName = match.group(1)
                        if ECallName in gECallCnt.keys():
                            gECallCnt[ECallName] += 1
                        else:
                            gECallCnt[ECallName] = 1
    for ECallName in gECallCnt.keys():
        print(str(gECallCnt[ECallName])+" "+args.kind+" "+ECallName)


if __name__ == "__main__":
    main()
