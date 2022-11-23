import os, argparse, subprocess
from tqdm.auto import tqdm
import re, json
import multiprocessing as mp
import datetime


# Script Settings
MAX_WORKERS = 16
CHUNK_SIZE = 5


crash_report = dict()

def check_aslr():
    with open("/proc/sys/kernel/randomize_va_space", "r") as f:
        if (f.read().strip() != "0"):
            print("ASLR is enabled, please disable it!")
            exit(1)


def get_crash_info(binary, crash_file):
    cmd = [binary, crash_file]
    # print(f"{cmd}")
    try:
        logs = subprocess.run(cmd, capture_output=True, timeout=3)
    except subprocess.TimeoutExpired:
        print(f"Timeout input {crash_file}!")
        return
    error_regex = re.compile(r"\[SGXSan\] (ERROR|WARNING): (.*)", flags=re.IGNORECASE)
    backtrace_regex = re.compile(r"== SGXSan Backtrace BEG ==((?:.|\n)*?)== SGXSan Backtrace END ==")
    error = error_regex.findall(logs.stderr.decode("utf-8"))

    backtrace = backtrace_regex.findall(logs.stderr.decode("utf-8"))
    pc_regex = r"==\d+==ERROR:\s?:.|\s*?pc\s(0x.*?)\s"
    pc_value = re.findall(pc_regex, logs.stderr.decode("utf-8"))
    error_tag = ""
    if (len(error) == 1):
        error_tag = " :".join(error[0])
    else:
        for e in error:
            error_tag += " :".join(e) + " | "
    
    # print(logs)
    # print(f"Log: {logs}")
    # print(f"Error: {error_tag}")


    if (len(pc_value) == 1):
        pc_value = pc_value[0]
    else:
        pc_value = None


    if error_tag not in crash_report:
        crash_report[error_tag] = dict()
        crash_report[error_tag]["pcs"] = dict()
        crash_report[error_tag]["num_crashes"] = 0
        crash_report[error_tag]["inputs"] = []
    crash_report[error_tag]["num_crashes"] += 1
    crash_report[error_tag]["inputs"].append(os.path.basename(crash_file))
    if pc_value not in crash_report[error_tag]["pcs"]:
        crash_report[error_tag]["pcs"][pc_value] = 0
    crash_report[error_tag]["pcs"][pc_value] += 1
    # crash_report[error]["backtrace"] = backtrace

    if "SGXSan" in str(logs):
        print(f"Error: {error_tag}")




def filter_crashes(binary, crashes_dir):
    if (binary.startswith("..")):
        binary = os.path.abspath(binary)
    if (crashes_dir.startswith("..")):
        crashes_dir = os.path.abspath(crashes_dir)

    if (not os.path.exists(binary)):
        print(f"Fuzzer binary {binary} not found!")
        return
    if (not os.path.exists(crashes_dir)):
        print(f"Crashes directory {crashes_dir} not found!")
        return
    
    # get_crash_info(binary, os.path.join(crashes_dir, "crash-afc2e0ef6ec37f0974f71d36c98191e9be4df691"))

    for f in tqdm(os.listdir(crashes_dir), position=0):
        if (f.startswith("crash-")):
            crash_file = os.path.join(crashes_dir, f)
            # print(crash_file)
            get_crash_info(binary, crash_file)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Filter crashes and generate result.json")
    parser.add_argument("-b", "--binary", help="path of fuzzer binary", required=True)
    parser.add_argument("-c", "--crashes", help="path of crashes directory", required=True)
    parser.add_argument("-p", "--prefix", help="prefix of result file", required=True)

    args = parser.parse_args()
    check_aslr()

    filter_crashes(args.binary, args.crashes)


    binary_name = os.path.basename(args.binary)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    result_file = f"{args.prefix}-{binary_name}-{timestamp}.result.json"
    json.dump(crash_report, open(result_file, "w"), indent=4)
    
    # print(crash_report)
    
    print(f"Saved result to {result_file}")



    # fileter_crashes

    