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
        if (f.read().strip() != "0"):
            print("ASLR is enabled, please disable it!")
            exit(1)


def get_crash_info(binary, crash_file, extra_opt: list, test_dir):
    cmd: str = binary+" "+crash_file
    if(extra_opt):
        cmd = cmd+" " + " ".join(extra_opt)
    cmd_list = cmd.split()
    # print(f"{cmd_list}")

    # Run crash
    try:
        logs = subprocess.run(
            cmd_list, capture_output=True, timeout=60, cwd=test_dir)
    except subprocess.TimeoutExpired:
        print(f"Timeout input {crash_file}!")
        return
    stderr = logs.stderr.decode("utf-8")

    sgxsan_error_regex = re.compile(
        r"\[SGXSan\] ((?:ERROR|WARNING): .*)", flags=re.IGNORECASE)
    sgxsan_error = sgxsan_error_regex.findall(stderr)
    error_tag = " | ".join(sgxsan_error)

    bt_regex = re.compile(
        r"== SGXSan Backtrace BEG ==\n(.*?)== SGXSan Backtrace END ==", re.DOTALL)
    bt_list = bt_regex.findall(stderr)
    bt_str = "======================== BREAK LINE ========================\n".join(
        bt_list)
    backtrace = hashlib.sha256(bt_str.encode()).hexdigest()
    if bt_str and "ERROR: libFuzzer: out-of-memory" not in stderr:
        assert error_tag

    pc_regex = re.compile(
        r"==\d+==ERROR:.*?\bpc\s+(0x[A-Fa-f0-9]*?)", re.DOTALL)
    pc_value = re.search(pc_regex, stderr)

    if error_tag not in crash_report:
        crash_report[error_tag] = {}
    if backtrace not in crash_report[error_tag]:
        crash_report[error_tag][backtrace] = {}

    if "num_crashes" not in crash_report[error_tag][backtrace]:
        crash_report[error_tag][backtrace]["num_crashes"] = 0
    crash_report[error_tag][backtrace]["num_crashes"] += 1

    if "inputs" not in crash_report[error_tag][backtrace]:
        crash_report[error_tag][backtrace]["inputs"] = []
    crash_report[error_tag][backtrace]["inputs"].append(
        os.path.basename(crash_file))

    if "pcs" not in crash_report[error_tag][backtrace]:
        crash_report[error_tag][backtrace]["pcs"] = {}
    if pc_value not in crash_report[error_tag][backtrace]["pcs"]:
        crash_report[error_tag][backtrace]["pcs"][pc_value] = 0
    crash_report[error_tag][backtrace]["pcs"][pc_value] += 1

    if error_tag not in crash_report_simple:
        crash_report_simple[error_tag] = {}
    if backtrace not in crash_report_simple[error_tag]:
        crash_report_simple[error_tag][backtrace] = {}

    if "num_crashes" not in crash_report_simple[error_tag][backtrace]:
        crash_report_simple[error_tag][backtrace]["num_crashes"] = 0
    crash_report_simple[error_tag][backtrace]["num_crashes"] += 1

    if "inputs" not in crash_report_simple[error_tag][backtrace]:
        crash_report_simple[error_tag][backtrace]["inputs"] = []
    if not error_tag or not backtrace or not crash_report_simple[error_tag][backtrace]["inputs"]:
        crash_report_simple[error_tag][backtrace]["inputs"].append(os.path.basename(
            crash_file))

    if "pcs" not in crash_report_simple[error_tag][backtrace]:
        crash_report_simple[error_tag][backtrace]["pcs"] = {}
    if pc_value not in crash_report_simple[error_tag][backtrace]["pcs"]:
        crash_report_simple[error_tag][backtrace]["pcs"][pc_value] = 0
    crash_report_simple[error_tag][backtrace]["pcs"][pc_value] += 1

    if "hash2bt" not in crash_report:
        crash_report["hash2bt"] = {}
    crash_report["hash2bt"][backtrace] = bt_str.split("\n")
    if "hash2bt" not in crash_report_simple:
        crash_report_simple["hash2bt"] = {}
    crash_report_simple["hash2bt"][backtrace] = bt_str.split("\n")


def filter_crashes(binary, crashes_dir, extra_opt, test_dir):
    if (not os.path.isfile(binary)):
        print(f"Fuzzer binary {binary} not found!")
        return
    if (not os.path.isdir(crashes_dir)):
        print(f"Crashes directory {crashes_dir} not found!")
        return
    if (not os.path.isdir(test_dir)):
        print(f"Test directory {test_dir} not found!")
        return

    for f in tqdm(os.listdir(crashes_dir)):
        if (f.startswith("crash-")):
            crash_file = os.path.join(crashes_dir, f)
            # print(crash_file)
            get_crash_info(binary, crash_file, extra_opt, test_dir)


def main():
    parser = argparse.ArgumentParser(
        description="Filter crashes and generate result.json")
    parser.add_argument(
        "-b", "--binary", help="Path of fuzzer binary", required=True)
    parser.add_argument("-c", "--crashes",
                        help="Path of crashes directory", required=True)
    parser.add_argument(
        "-p", "--prefix", help="Prefix of result file")
    parser.add_argument(
        "--test-dir", default=".", help="Test directory", metavar="<e.g. ./SGX_APP/sgx-wallet>")
    parser.add_argument(
        "--extra-opt", help="Suffix command options", nargs="+")
    args = parser.parse_args()

    check_aslr()

    filter_crashes(os.path.abspath(args.binary),
                   os.path.abspath(args.crashes),
                   args.extra_opt,
                   os.path.abspath(args.test_dir),
                   )

    binary_name = os.path.basename(args.binary)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    result_file = f"{binary_name}-{timestamp}.result.json"
    if args.prefix:
        result_file = args.prefix+"-"+result_file
    simple_result_file = f"{binary_name}-{timestamp}-simple.result.json"
    if args.prefix:
        simple_result_file = args.prefix+"-"+simple_result_file
    json.dump(crash_report, open(result_file, "w"), indent=4)
    json.dump(crash_report_simple, open(simple_result_file, "w"), indent=4)

    # print(crash_report)

    print(f"Saved result to {result_file}")


if __name__ == "__main__":
    main()
