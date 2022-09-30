import os, argparse, subprocess
from tqdm.auto import tqdm
import re, json
import multiprocessing as mp

crash_report = dict()

def check_aslr():
    with open("/proc/sys/kernel/randomize_va_space", "r") as f:
        if (f.read().strip() != "0"):
            print("ASLR is enabled, please disable it!")
            exit(1)


def filter_crashes(bin, crashes_dir):
    if (bin.startswith("..")):
        bin = os.path.abspath(bin)
    if (crashes_dir.startswith("..")):
        crashes_dir = os.path.abspath(crashes_dir)

    if (not os.path.exists(bin)):
        print(f"Fuzzer binary {bin} not found!")
        return
    if (not os.path.exists(crashes_dir)):
        print(f"Crashes directory {crashes_dir} not found!")
        return
    
    for f in tqdm(os.listdir(crashes_dir), position=0):
        if (f.startswith("crash-")):
            crash_file = os.path.join(crashes_dir, f)
            # print(crash_file)

            cmd = [bin, crash_file]
            try:
                logs = subprocess.run(cmd, capture_output=True, timeout=3)
            except subprocess.TimeoutExpired:
                print(f"Timeout input {crash_file}!")
                continue


            error_regex = re.compile(r"\[SGXSan error\] (.*)")
            backtrace_regex = re.compile(r"== SGXSan Backtrace BEG ==((?:.|\n)*?)== SGXSan Backtrace END ==")
            error = error_regex.findall(logs.stderr.decode("utf-8"))
            backtrace = backtrace_regex.findall(logs.stderr.decode("utf-8"))
            pc_regex = r"==\d+==ERROR:\s?:.|\s*?pc\s(0x.*?)\s"
            pc_value = re.findall(pc_regex, logs.stderr.decode("utf-8"))

            if (len(error) == 1):
                error = error[0]
            else:
                error = " ".join(error)

            if (len(pc_value) == 1):
                pc_value = pc_value[0]
            else:
                pc_value = None


            if error not in crash_report:
                crash_report[error] = dict()
                crash_report[error]["pcs"] = dict()
                crash_report[error]["num_crashes"] = 0
                crash_report[error]["inputs"] = []

            crash_report[error]["num_crashes"] += 1
            crash_report[error]["inputs"].append(f)
            if pc_value not in crash_report[error]["pcs"]:
                crash_report[error]["pcs"][pc_value] = 0
            crash_report[error]["pcs"][pc_value] += 1
            # crash_report[error]["backtrace"] = backtrace


            
                
                # crash_report[error]["backtrace"] = backtrace
            
    # print(crash_file)
                
    



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Filter crashes and generate result.json")
    parser.add_argument("-b", "--binary", help="path of fuzzer binary", required=True)
    parser.add_argument("-c", "--crashes", help="path of crashes directory", required=True)

    args = parser.parse_args()
    check_aslr()

    filter_crashes(args.binary, args.crashes)

    json.dump(crash_report, open("result.json", "w"), indent=4)


    # fileter_crashes

    