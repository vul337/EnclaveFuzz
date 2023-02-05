#!/usr/bin/python3
import json
import argparse
import os
import re
import chardet
import tqdm


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--edl-json', metavar="<xxx.edl.json>")
    parser.add_argument('src_dir', metavar="<source directory>")
    parser.add_argument('--kind', default="Fuzzer2.0")
    args = parser.parse_args()

    ecalls = []
    with open(args.edl_json) as edl_json_file:
        edl_json = json.load(edl_json_file)
        ecalls = list(edl_json["trusted"])
    print("Total %d ECalls" % len(ecalls))

    files = []
    for dirpath, dirnames, filenames in os.walk(args.src_dir):
        for filename in filenames:
            if filename != ".git" and re.match(".*\.c[^.]*", filename):
                f_abs_path = os.path.join(dirpath, filename)
                files.append(f_abs_path)

    ecall_insert_times = {}
    for file in tqdm.tqdm(files):
        with open(file, 'r+', errors="backslashreplace") as f:
            content = f.read()
            modified = False
            for ecall in ecalls:
                LogEnterFuncName = "SGXSanLogEnter" if args.kind == "Fuzzer2.0" else "LogEnter"
                content, n = re.subn(
                    r"(\b" + ecall+r"\s*?\([^(){}]*?\)[^(){}]*?\{(?!\n    "+LogEnterFuncName+r"))", r"\1\n    "+LogEnterFuncName+r"(__func__);", content, flags=re.DOTALL)
                if n > 0:
                    modified = True
                    if ecall not in ecall_insert_times:
                        ecall_insert_times[ecall] = 0
                    ecall_insert_times[ecall] += n
            if modified:
                f.seek(0, os.SEEK_SET)
                head = \
                    "#if defined(__cplusplus)\n" \
                    "extern \"C\"{\n" \
                    "#endif\n" \
                    "void SGXSanLogEnter(const char *str);\n" \
                    "#if defined(__cplusplus)\n" \
                    "}\n" \
                    "#endif\n" if args.kind == "Fuzzer2.0" else "#include \"kafl_hc.h\"\n"
                content = head + content
                f.write(content)

    print(json.dumps(ecall_insert_times, indent=4))


if __name__ == "__main__":
    main()
