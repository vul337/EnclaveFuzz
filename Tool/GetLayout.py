#!/usr/bin/python3
import re
import os
import argparse
import subprocess
import json


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('object', nargs="+", metavar="<xxx.o>")
    parser.add_argument(
        '-o', '--output', metavar="<e.g. target.json>", required=True)
    args = parser.parse_args()

    objects = args.object
    for object in objects:
        print("== Process "+object+" ==")
        object_abs = os.path.abspath(object)
        output_abs = os.path.abspath(args.output)

        target_json = {}
        if os.path.exists(output_abs):
            with open(output_abs) as target_file:
                try:
                    target_json = json.load(target_file)
                except json.decoder.JSONDecodeError:
                    pass

        res = subprocess.run(
            ["nm", "-C", "--defined-only", object_abs], capture_output=True)
        funcs = []
        lines = res.stdout.decode("utf-8").splitlines()
        for line in lines:
            match = re.match(r"\w+\s+([a-zA-Z])\s+(.*)", line)
            if match:
                if match.group(1) == "T" or match.group(1) == "t":
                    funcs.append(match.group(2))

        target_json[object] = funcs
        with open(output_abs, "w") as target_file:
            json.dump(target_json, target_file)


if __name__ == "__main__":
    main()
