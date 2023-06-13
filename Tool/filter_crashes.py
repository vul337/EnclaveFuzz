#!/bin/python3
import os
import argparse
import subprocess
from tqdm.auto import tqdm
import re
import json
import multiprocessing as mp
import datetime
import hashlib

# Script Settings
MAX_WORKERS = 16
CHUNK_SIZE = 5


crash_report = {}
crash_report_simple = {}


def check_aslr():
    with open("/proc/sys/kernel/randomize_va_space", "r") as f:
        if f.read().strip() != "0":
            print("ASLR is enabled, please disable it!")
            exit(1)


def update2dict(bt_str, error_tag, pc_value, crash_file, do_simple):
    if do_simple and "ERROR: Host" in error_tag:
        error_tag = "Don't care host error"
        bt_str = ""
        pc_value = ""
    dict = crash_report_simple if do_simple else crash_report
    bt_hash = hashlib.sha256(bt_str.encode()).hexdigest() if bt_str else ""

    filter1 = pc_value
    filter2 = bt_hash
    filter3 = error_tag

    if filter1 not in dict:
        dict[filter1] = {}
    if filter2 not in dict[filter1]:
        dict[filter1][filter2] = {}
    if filter3 not in dict[filter1][filter2]:
        dict[filter1][filter2][filter3] = {}

    if "num_crashes" not in dict[filter1][filter2][filter3]:
        dict[filter1][filter2][filter3]["num_crashes"] = 0
    dict[filter1][filter2][filter3]["num_crashes"] += 1

    if "inputs" not in dict[filter1][filter2][filter3]:
        dict[filter1][filter2][filter3]["inputs"] = []
    if not do_simple:
        dict[filter1][filter2][filter3]["inputs"].append(os.path.basename(crash_file))
    elif (
        not filter1
        or not filter2
        or not filter3
        or not dict[filter1][filter2][filter3]["inputs"]
    ):
        dict[filter1][filter2][filter3]["inputs"].append(os.path.basename(crash_file))

    if "hash2bt" not in dict:
        dict["hash2bt"] = {}
    if bt_hash:
        dict["hash2bt"][bt_hash] = bt_str.split("\n")


def get_crash_info(binary, crash_file, extra_opt: list, test_dir, timeout, kind):
    cmd: str = binary + " " + crash_file
    if extra_opt:
        cmd = cmd + " " + " ".join(extra_opt)
    cmd_list = cmd.split()
    # print(f"{cmd_list}")

    # Run crash
    try:
        logs = subprocess.run(
            cmd_list,
            timeout=timeout,
            cwd=test_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except subprocess.TimeoutExpired:
        print(f"\nTimeout input {crash_file}!")
        return
    report = logs.stdout.decode("utf-8")
    # print(report)

    sgxsan_error_regex = re.compile(
        r"\[SGXSan\] ERROR:.*"
        r"|\[SGXSan\] WARNING:\s*?Detect Double-Fetch Situation, and modify it with fuzz data"
        r"|ERROR: libFuzzer:.*",
        flags=re.IGNORECASE,
    )
    sgxsan_error = sgxsan_error_regex.findall(report)
    error_tag = " | ".join(sgxsan_error)

    bt_regex = re.compile(
        r"== SGXSan Backtrace BEG ==\n(.*?)== SGXSan Backtrace END ==", re.DOTALL
    )
    bt_list = bt_regex.findall(report)
    bt_str = "======================== BREAK LINE ========================\n".join(
        bt_list
    )

    pc_regex = re.compile(r"ERROR:.*?\bpc\s+(0x[A-Fa-f0-9]*)", re.DOTALL)
    res = re.search(pc_regex, report)
    pc_value = "Unknown"
    if res:
        pc_value = res[1]

    if "NOTE: fuzzing was not performed, you have only" in report:
        error_tag = ""
        bt_str = ""

    update2dict(bt_str, error_tag, pc_value, crash_file, False)
    update2dict(bt_str, error_tag, pc_value, crash_file, True)


def filter_crashes(
    binary, crashes_dir, extra_opt, test_dir, timeout, kind, result_file
):
    if not os.path.isfile(binary):
        print(f"Fuzzer binary {binary} not found!")
        return
    if not os.path.isdir(crashes_dir):
        print(f"Crashes directory {crashes_dir} not found!")
        return
    if not os.path.isdir(test_dir):
        print(f"Test directory {test_dir} not found!")
        return

    for f in tqdm(sorted(os.listdir(crashes_dir))):
        if kind != "KAFL" and not f.startswith("crash-"):
            continue
        crash_file = os.path.join(crashes_dir, f)
        # print(crash_file)
        get_crash_info(binary, crash_file, extra_opt, test_dir, timeout, kind)
        json.dump(crash_report, open(result_file, "w"), indent=4)
        json.dump(crash_report_simple, open("simple-" + result_file, "w"), indent=4)


def main():
    parser = argparse.ArgumentParser(
        description="Filter crashes and generate result.json"
    )
    parser.add_argument("-b", "--binary", help="Path of fuzzer binary", required=True)
    parser.add_argument(
        "-c", "--crashes", help="Path of crashes directory", required=True
    )
    parser.add_argument("-p", "--prefix", help="Prefix of result file", default="")
    parser.add_argument(
        "--test-dir",
        default=".",
        help="Test directory",
        metavar="<e.g. ./SGX_APP/sgx-wallet>",
    )
    parser.add_argument("--extra-opt", help="Suffix command options", nargs="+")
    parser.add_argument("--timeout", default=60)
    parser.add_argument(
        "-k", "--kind", default="libFuzzer", help="KAFL's or LibFuzzer's Error Report"
    )
    args = parser.parse_args()
    if args.kind != "KAFL":
        check_aslr()

    binary_name = os.path.basename(args.binary)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    result_file = args.prefix + f"{binary_name}-{timestamp}.result.json"

    filter_crashes(
        os.path.abspath(args.binary),
        os.path.abspath(args.crashes),
        args.extra_opt,
        os.path.abspath(args.test_dir),
        int(args.timeout),
        args.kind,
        result_file,
    )

    # print(crash_report)

    print(f"Saved result to {result_file}")


if __name__ == "__main__":
    main()
