#!/usr/bin/python3
import argparse
import os
import datetime
import re
import matplotlib.pyplot as plt
import tqdm
import multiprocessing
import functools
import threading
import time


def data_from_file(file_abs: str) -> tuple:
    enclave_cov = 0
    enclave_block = 0
    interest_cov = 0
    interest_block = 0
    with open(file_abs) as cov_file:
        content = cov_file.read()
        m = re.match(
            "EnclaveCoverage:\t\t([0-9]+)/([0-9]+).*?\nInterestingCoverage:\t([0-9]+)/([0-9]+)",
            content,
        )
        if m:
            enclave_cov = int(m.group(1))
            enclave_block = int(m.group(2))
            interest_cov = int(m.group(3))
            interest_block = int(m.group(4))

    enclave_cov_pct = enclave_cov * 100 / enclave_block if enclave_block else 0
    interest_cov_pct = interest_cov * 100 / interest_block if interest_block else 0
    effectiveness = interest_cov * 100 / enclave_cov if enclave_cov else 0
    return enclave_cov_pct, interest_cov_pct, effectiveness


map = {}
map_lock = threading.Lock()


def update_map_cb(data: tuple, delta_time, pbar):
    map_lock.acquire()
    try:
        map[delta_time] = data
    finally:
        map_lock.release()
        pbar.update()


def data_from_dir(dir, max_time):
    map.clear()
    start_time = None
    pool = multiprocessing.Pool()
    file_names = sorted(os.listdir(dir))
    pbar = tqdm.tqdm(total=len(file_names))
    for file_name in file_names:
        if file_name.startswith("cov_"):
            record_time = datetime.datetime.strptime(file_name, "cov_%Y_%m_%d_%H_%M_%S")
            if start_time == None:
                start_time = record_time
            delta = record_time - start_time
            delta_time = delta.days * 24 + delta.seconds / 3600

            if delta_time <= max_time:
                cb = functools.partial(update_map_cb, delta_time=delta_time, pbar=pbar)
                file_abs = os.path.join(dir, file_name)
                pool.apply_async(
                    data_from_file,
                    args=(file_abs,),
                    callback=cb,
                    error_callback=lambda x: print(x),
                )
            else:
                pbar.update()
    pool.close()
    pool.join()
    pbar.close()
    return map


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ef-dir", default="")
    parser.add_argument("--sf-dir", default="")
    parser.add_argument("--max-hour", default=24)
    parser.add_argument("--out", default="./Cov.jpg")
    args = parser.parse_args()

    fig = plt.figure(figsize=(6, 6))
    ax1 = fig.add_subplot(3, 1, 1)
    ax2 = fig.add_subplot(3, 1, 2)
    ax3 = fig.add_subplot(3, 1, 3)

    ef_map = {}
    if args.ef_dir:
        print("== Processing data of EnclaveFuzz ==")
        ef_map = data_from_dir(args.ef_dir, args.max_hour)
        ef_h, ef_data = zip(*sorted(ef_map.items()))
        ef_enclave_cov, ef_interest_cov, ef_effectiveness = zip(*ef_data)
        ax1.plot(ef_h, ef_enclave_cov, label="EnclaveFuzz")
        ax2.plot(ef_h, ef_interest_cov, label="EnclaveFuzz")
        ax3.plot(ef_h, ef_effectiveness, label="EnclaveFuzz")

    sf_map = {}
    if args.sf_dir:
        print("== Processing data of SGXFuzz ==")
        sf_map = data_from_dir(args.sf_dir, args.max_hour)
        sf_h, sf_data = zip(*sorted(sf_map.items()))
        sf_enclave_cov, sf_interest_cov, sf_effectiveness = zip(*sf_data)
        ax1.plot(sf_h, sf_enclave_cov, label="SGXFuzz")
        ax2.plot(sf_h, sf_interest_cov, label="SGXFuzz")
        ax3.plot(sf_h, sf_effectiveness, label="SGXFuzz")

    ax1.legend()
    ax1.grid()
    ax1.set_ylabel(r"Enclave Cov. (%)")

    ax2.legend()
    ax2.grid()
    ax2.set_ylabel(r"Interest Cov. (%)")

    ax3.legend()
    ax3.grid()
    ax3.set_xlabel("Time (Hour)")
    ax3.set_ylabel(r"Effectiveness (%)")

    if not os.path.exists(os.path.dirname(args.out)):
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
    plt.tight_layout()
    plt.savefig(args.out)


if __name__ == "__main__":
    main()
