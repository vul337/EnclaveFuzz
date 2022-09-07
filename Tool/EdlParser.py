#!/usr/bin/python3
"""
EDL File Parser
"""

import re
import os
import json
import argparse


class EdlParser:

    def get_array_cnt_from_dim_str(self, array_dim_str):
        if array_dim_str != "":
            arr_cnts = [int(dim.strip(), base=0)
                        for dim in re.findall(r"\[(.+?)\]", array_dim_str)]
            arr_cnt = arr_cnts[0]
            arr_total_cnt = 1
            for cnt in arr_cnts:
                arr_total_cnt *= cnt
            return arr_cnt, arr_total_cnt
        else:
            return -1, -1

    def get_isary_count(self, type):
        for included_file in self.included_fils+[x[0] for x in self.edl_file_and_imported_funcs_list]:
            with open(included_file) as f:
                # erase comments in edl file
                content = re.sub(
                    re.compile(r"(/\*.*?\*/|//.*?\n)", re.DOTALL), "", f.read()
                )
                match = re.search(r"typedef\s+(\w+?)\s+" +
                                  type+r"(.*);", content)
                if match:
                    return self.get_array_cnt_from_dim_str(match.group(2).strip())
        print("Not found real definition of [isary] type: "+type + "\n" +
              "Please check search path(--search-path) or include path(-I)\n")
        os.abort
        return -1, -1

    def analyse_c_param(self, c_param):
        match = re.match(r"^(.+?)(\b\w+\b)\s*((\[.+?\])*)$", c_param)
        assert match
        param_type = match.group(1).strip()
        param_name = match.group(2)
        arr_dims = (match.group(3) or "").strip()
        (arr_cnt, arr_total_cnt) = self.get_array_cnt_from_dim_str(arr_dims)
        return param_type, param_name, arr_cnt, arr_total_cnt

    def get_params_edl_infos(self, params):
        params_edl_infos = {}
        for param_pos, param in enumerate(params):
            param_edl_infos = {}
            c_param = ""
            # when void parameter appear, there is must only one parameter
            if param == "void":
                assert len(params) == 1
                break
            # read attribute keywords from [...]
            keywords_match = re.match(r"^\[(.*?)\](.+)$", param)
            if keywords_match:
                # get each attribute keyword
                for keyword_match in re.findall(r"([^,]+)(,|$)", keywords_match.group(1)):
                    keyword = keyword_match[0].strip()
                    key_value_match = re.match(r"^([^=]+)=([^=]+)$", keyword)
                    # whether it's a "key=value" attribute keyword
                    if key_value_match:
                        key = key_value_match[1].strip()
                        value = key_value_match[2].strip()
                        # value may be a constant int, e.g. [size=10] or [count=10]
                        co_param_pos = -1
                        if not re.match(r"^[0-9]+$", value):
                            for _co_param_pos, co_param in enumerate(params):
                                if _co_param_pos != param_pos and re.search(
                                    r"\b" + value + r"\b", co_param
                                ):
                                    co_param_pos = _co_param_pos
                                    break
                            assert co_param_pos != -1 and co_param_pos != param_pos
                            param_edl_infos[key] = {
                                "co_param": value, "co_param_pos": co_param_pos}
                        else:
                            param_edl_infos[key] = int(value)
                    else:
                        # not a "key=value" attribute keyword
                        param_edl_infos[keyword] = True
                c_param = keywords_match.group(2).strip()
            else:
                c_param = param.strip()
            # param_edl_infos["position"] = param_pos
            (param_type, param_name, arr_cnt,
             arr_total_cnt) = self.analyse_c_param(c_param)
            param_edl_infos["full_param"] = param
            param_edl_infos["c_param"] = c_param
            param_edl_infos["type"] = param_type
            param_edl_infos["name"] = param_name
            if arr_cnt != -1:
                param_edl_infos["c_array"] = True
                assert (
                    param_edl_infos.get("user_check")
                    or param_edl_infos.get("in")
                    or param_edl_infos.get("out")
                ) and (
                    param_edl_infos.get("size") == None
                    and param_edl_infos.get("count") == None
                )
                param_edl_infos["c_array_count"] = arr_cnt
                param_edl_infos["c_array_total_count"] = arr_total_cnt
            elif "isary" in param_edl_infos.keys() and param_edl_infos["isary"]:
                (arr_cnt, arr_total_cnt) = self.get_isary_count(
                    param_edl_infos["type"])
                param_edl_infos["c_array_count"] = arr_cnt
                param_edl_infos["c_array_total_count"] = arr_total_cnt

            params_edl_infos[param_pos] = param_edl_infos
        return params_edl_infos

    def process_func_declars(self, func_declars, speicified_funcs):
        funcs_info = {}
        for func_declar in re.findall(r"([^;]*);", func_declars):
            # get pretty string
            func_declar = re.sub(r"\s+", " ", func_declar).strip()
            if func_declar == "":
                continue

            # process func declaration
            func_info = {}
            # 1. process func type
            # char *func([out, size=size] char *s, int size, [user_check] void *stream)
            # public SSL_METHOD *ecall_SSLv23_method(void);
            match = re.match(
                r"^(.+?\s?\*?)\s?(\b\w+\b)\s*\((.*?)\)(.*)$", func_declar)
            assert match
            ret_and_func_begin_attr = match.group(1).strip()
            func_name = match.group(2)
            all_params = match.group(3).strip()
            func_end_attr = match.group(4).strip()
            # 2.1. process function's begin attributes
            for func_front_keyword in ["public", "cdecl"]:
                if re.search(r"\b" + func_front_keyword + r"\b", ret_and_func_begin_attr):
                    func_info[func_front_keyword] = True
            # 2.2. process return, as ocall return is also an input
            ret = (re.sub(r"(public|\[cdecl\])", "",
                          ret_and_func_begin_attr)).strip()
            func_info["return"] = {"type": ret}
            # 3. whether this function is included
            # if not speicify funcs then import all, related to 'from xxx import *'
            # if speicify funcs then import speicified, related to 'from xxx import a,b,c'
            if len(speicified_funcs) != 0 and func_name not in speicified_funcs:
                continue
            # 4. process func param with edl info
            params = [
                param[0].strip()
                for param in re.findall(r"((\[.*?\])?[^\[\],]+(\[.*?\])*)(,|$)", all_params)
            ]
            params_edl_infos = self.get_params_edl_infos(params)
            func_info["parameter"] = params_edl_infos
            # 5. conclude func info
            funcs_info[func_name] = func_info
        return funcs_info

    def parse_edl(self, edl_file, speicified_funcs):
        edl_info = {"trusted": {}, "untrusted": {}}
        with open(edl_file) as f:
            # erase comments in edl file
            content = re.sub(
                re.compile(r"(/\*.*?\*/|//.*?\n)", re.DOTALL), "", f.read()
            )

            # process current EDL file
            for domain in ["untrusted", "trusted"]:
                domain_pattern = re.compile(
                    r"\b" + domain + r"\s*\{(.*?)\}", re.DOTALL)
                for func_declars in re.findall(domain_pattern, content):
                    edl_info[domain] = {
                        **edl_info[domain],
                        **self.process_func_declars(func_declars, speicified_funcs),
                    }

        return edl_info

    def analyse_dependency(self, edl_file):
        if edl_file in self.processd_edl_files:
            return
        with open(edl_file) as f:
            self.processd_edl_files.append(edl_file)
            # erase comments in edl file
            content = re.sub(
                re.compile(r"(/\*.*?\*/|//.*?\n)", re.DOTALL), "", f.read()
            )
            # get included files
            for included_file in re.findall(r"\binclude\s*\"(.+?)\"", content):
                for directory in self.include_path_list:
                    abs_path = os.path.join(directory, included_file)
                    if os.path.exists(abs_path):
                        self.included_fils.append(abs_path.strip())
            # get external EDL files
            for extern_edl_file_and_funcs in re.findall(
                r"\bfrom\s+\"(.+?)\"\s+import\s+([^;]+);", content
            ):
                extern_edl_file = extern_edl_file_and_funcs[0].strip()
                if extern_edl_file in self.ignored_edl_files:
                    continue
                extern_edl_funcs = extern_edl_file_and_funcs[1].strip()
                # if 'from xxx import *', leave imported_funcs empty
                # if 'from xxx import a,b,c', set imported_funcs
                imported_funcs = []
                if extern_edl_funcs != "*":
                    imported_funcs = [
                        x[0].strip()
                        for x in re.findall(r"([^,]+)(,|$)", extern_edl_funcs)
                    ]

                has_resolved_extern_edl_file = False
                for directory in self.search_path_list:
                    abs_path = os.path.join(directory, extern_edl_file)
                    if os.path.exists(abs_path):
                        self.edl_file_and_imported_funcs_list.append(
                            (abs_path, imported_funcs))
                        self.analyse_dependency(abs_path)
                        has_resolved_extern_edl_file = True
                        break
                assert (
                    "Can't find external EDL file. Please check search path"
                    and has_resolved_extern_edl_file
                )

    def run(self):
        # analyse dependencies, get all related edl files and included headers
        self.analyse_dependency(self.edl_file)
        # parse EDL files
        edl_info = {"trusted": {}, "untrusted": {}}
        for edl_file_and_imported_funcs in self.edl_file_and_imported_funcs_list:
            res = self.parse_edl(*edl_file_and_imported_funcs)
            for domin in ["trusted", "untrusted"]:
                edl_info[domin] = {
                    **edl_info[domin],
                    **res[domin],
                }
        # output it
        with open(self.edl_file + ".json", "w") as edl_json:
            edl_json.write(json.dumps(edl_info, indent=4))

    def __init__(self, edl_file, search_path_list, include_path_list) -> None:
        self.edl_file = edl_file
        self.search_path_list = search_path_list
        self.include_path_list = include_path_list
        self.processd_edl_files = []
        self.edl_file_and_imported_funcs_list = [(self.edl_file, [])]
        self.included_fils = []
        self.ignored_edl_files = ["SGXSanRTEnclave.edl", "SanitizerCoverageRTEnclave.edl"]


def main():
    # prepare argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("edl", metavar="<EDL file>")
    parser.add_argument(
        "--search-path", action="append", metavar="<e.g. /opt/intel/sgxsdk/include>"
    )
    parser.add_argument(
        "-I", dest="include_path", action="append", metavar="<e.g. /opt/intel/sgxsdk/include>"
    )
    args = parser.parse_args()
    # prepare and process argument info
    edl_file = os.path.abspath(args.edl)
    search_path_list = [os.path.abspath(path)
                        for path in (args.search_path or [])]
    search_path_list.append(os.path.dirname(edl_file))
    include_path_list = [os.path.abspath(path)
                         for path in (args.include_path or [])]
    include_path_list.append(os.getcwd())
    parser = EdlParser(edl_file, search_path_list, include_path_list)
    parser.run()


if __name__ == "__main__":
    main()
