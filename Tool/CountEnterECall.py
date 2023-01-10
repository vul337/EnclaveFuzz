#!/usr/bin/python3
import argparse
import os
import re
import multiprocessing
import threading
import functools
from tqdm.auto import tqdm

gECallCnt = {}
updateLock = threading.Lock()


def Update(ECallCnt: dict, pbar):
    updateLock.acquire()
    try:
        for key in ECallCnt.keys():
            if key not in gECallCnt.keys():
                gECallCnt[key] = 0
            gECallCnt[key] += ECallCnt[key]
    finally:
        updateLock.release()
        pbar.update()


def Count(log_abs, word, kind) -> dict:
    pECallCnt = {}
    with open(log_abs, errors="backslashreplace") as log_file:
        lines = log_file.readlines()
        for line in lines:
            match = re.search(
                word + (r"\s+(\w+)" if kind == "EnclaveFuzz" else r"\s+(\w+.*)"), line
            )
            if match:
                ECallName = match.group(1)
                if ECallName in pECallCnt.keys():
                    pECallCnt[ECallName] += 1
                else:
                    pECallCnt[ECallName] = 1
    return pECallCnt


def main():
    parser = argparse.ArgumentParser(
        description="Analyse all *.log in <log_dir> to count Enter ECall_XXX"
    )
    parser.add_argument("log_dir")
    parser.add_argument("--word", default="Enter")
    parser.add_argument("--kind", default="EnclaveFuzz")
    args = parser.parse_args()

    pool = multiprocessing.Pool()
    log_files = sorted(os.listdir(args.log_dir))
    pbar = tqdm(total=len(log_files))
    cb = functools.partial(Update, pbar=pbar)
    for log in log_files:
        if args.kind == "EnclaveFuzz" and not log.endswith(r".log"):
            pbar.update
            continue
        log_abs = os.path.join(args.log_dir, log)
        if not os.path.exists(log_abs):
            pbar.update
            continue
        pool.apply_async(
            Count,
            args=(log_abs, args.word, args.kind),
            callback=cb,
            error_callback=lambda x: print(x),
        )
    pool.close()
    pool.join()
    pbar.close()
    for ECallName in gECallCnt.keys():
        print(str(gECallCnt[ECallName]) + " " + args.word + " " + ECallName)


if __name__ == "__main__":
    main()
