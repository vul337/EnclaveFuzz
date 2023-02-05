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
        with open(file, 'r+b') as f:
            f.seek(0, os.SEEK_SET)
            content_raw = f.read()
            encoding = chardet.detect(content_raw)
            content = content_raw.decode(encoding["encoding"])
            modified = False
            for ecall in ecalls:
                content, n = re.subn(
                    r"(\b" + ecall+r"\b[^(){}]*?\([^(){}]*?\)[^(){}]*?\{(?!\n    LogEnter))", r"\1\n    LogEnter(__func__);", content, flags=re.DOTALL)
                if n > 0:
                    modified = True
                    if ecall not in ecall_insert_times:
                        ecall_insert_times[ecall] = 0
                    ecall_insert_times[ecall] += n
            if modified:
                f.seek(0, os.SEEK_SET)
                content = "#include \"kafl_hc.h\"\n"+content
                content_raw = content.encode(encoding["encoding"])
                f.write(content_raw)

    print(json.dumps(ecall_insert_times, indent=4))


if __name__ == "__main__":
    main()
