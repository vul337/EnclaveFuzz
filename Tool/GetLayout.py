#!/usr/bin/python3
import re
import os
import argparse
import subprocess
import json


def main():
    parser = argparse.ArgumentParser(prefix_chars="+")
    parser.add_argument(
        "+o",
        "++output_dir",
        required=True,
    )
    args = parser.parse_args(getScriptArgs())

    object = getCurrentProgram()
    if not os.path.exists(args.output_dir):
        os.mkdir(args.output_dir)
    output_abs = os.path.abspath(os.path.join(args.output_dir, str(object.getExecutablePath()).replace("/","_").replace(".","_")))

    target_json = {}
    if os.path.exists(output_abs):
        with open(output_abs) as target_file:
            try:
                target_json = json.load(target_file)
            except json.decoder.JSONDecodeError:
                pass

    funcs = []
    for func in object.getFunctionManager().getFunctions(True):
        if not func.isThunk():
            func_name = func.getName()
            funcs.append(func_name)
            # print("**** " + func_name)

    target_json[object.getExecutablePath()] = funcs
    with open(output_abs, "w") as target_file:
        json.dump(target_json, target_file)


main()
