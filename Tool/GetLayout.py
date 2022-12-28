#!/usr/bin/python3
import sys
import os
import argparse
import subprocess
import json


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('object', metavar="<xxx.o>")
    parser.add_argument(
        '-o', '--output', metavar="<e.g. target.json>", required=True)
    args = parser.parse_args()

    object_abs = os.path.abspath(args.object)
    output_abs = os.path.abspath(args.output)

    target_json = {}
    if os.path.exists(output_abs):
        with open(output_abs) as target_file:
            try:
                target_json = json.load(target_file)
            except json.decoder.JSONDecodeError:
                pass

    res = subprocess.run(
        ["nm", "--defined-only", object_abs], capture_output=True)
    funcs = []
    for line in res.stdout.decode("utf-8").splitlines():
        cols = line.split()
        if cols[1] == "T" or cols[1] == "t":
            funcs.append(cols[2])

    target_json[args.object] = funcs
    with open(output_abs, "w") as target_file:
        json.dump(target_json, target_file)


if __name__ == "__main__":
    main()
