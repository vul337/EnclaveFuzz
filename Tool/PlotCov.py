#!/usr/bin/python3
import argparse
import os
import datetime
import re
import matplotlib.pyplot as plt


def data_from_dir(dir, max_hour):
    start_time = None
    map = {}
    for file_name in sorted(os.listdir(dir)):
        if file_name.startswith("cov_"):
            time = datetime.datetime.strptime(file_name, "cov_%Y_%m_%d_%H_%M_%S")
            if start_time == None:
                start_time = time
            delta_time = time - start_time
            delta_hour = delta_time.days * 24 + delta_time.seconds / 3600

            if delta_hour <= max_hour:
                with open(os.path.join(dir, file_name)) as cov_file:
                    content = cov_file.read()
                    m = re.match(
                        "EnclaveCoverage:\t\t([0-9]+)/([0-9]+).*?\nInterestingCoverage:\t([0-9]+)/([0-9]+)",
                        content,
                    )
                    assert m
                    enclave_cov = int(m.group(1))
                    enclave_block = int(m.group(2))
                    interest_cov = int(m.group(3))
                    interest_block = int(m.group(4))

                    enclave_cov_pct = enclave_cov / enclave_block
                    interest_cov_pct = interest_cov / interest_block
                    if enclave_cov:
                        effectiveness = interest_cov / enclave_cov
                    else:
                        effectiveness = 0

                map[delta_hour] = (
                    enclave_cov_pct,
                    interest_cov_pct,
                    effectiveness,
                )
    return map


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ef-dir", default="")
    parser.add_argument("--sf-dir", default="")
    parser.add_argument("--max-hour", default=24)
    parser.add_argument("--out", default="./Cov.jpg")
    args = parser.parse_args()

    fig = plt.figure()
    ax = fig.add_subplot()

    ef_map = {}
    if args.ef_dir:
        ef_map = data_from_dir(args.ef_dir, args.max_hour)
        ef_h, ef_data = zip(*sorted(ef_map.items()))
        ef_enclave_cov, ef_interest_cov, ef_effectiveness = zip(*ef_data)
        ax.plot(ef_h, ef_enclave_cov, label="EnclaveFuzz-EnclaveCoverage")
        ax.plot(ef_h, ef_interest_cov, label="EnclaveFuzz-InterestCoverage")

    sf_map = {}
    if args.sf_dir:
        sf_map = data_from_dir(args.sf_dir, args.max_hour)
        sf_h, sf_data = zip(*sorted(sf_map.items()))
        sf_enclave_cov, sf_interest_cov, sf_effectiveness = zip(*sf_data)
        ax.plot(sf_h, sf_enclave_cov, label="SGXFuzz-EnclaveCoverage")
        ax.plot(sf_h, sf_interest_cov, label="SGXFuzz-InterestCoverage")

    ax.legend()
    ax.grid()
    ax.set_xlabel("Time (Hour)")
    ax.set_ylabel(r"Percentage")

    plt.savefig(args.out)


if __name__ == "__main__":
    main()
