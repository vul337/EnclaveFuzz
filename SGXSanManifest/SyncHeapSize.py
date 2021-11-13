import re
import sys
import os

if __name__ == '__main__':
    if len(sys.argv) <= 1:
        print("[SyncHeapSize.py] Please input configure file name")
        sys.exit(1)

    configure_file_name = sys.argv[1]
    # print(configure_file_name)
    if not os.path.exists(configure_file_name):
        print("[SyncHeapSize.py] Please input *valid* configure file name")
        sys.exit(1)

    heap_max_size_pattern = re.compile("<HeapMaxSize>(.*?)</HeapMaxSize>")
    heap_init_size_pattern = re.compile("<HeapInitSize>(.*?)</HeapInitSize>")
    heap_min_size_pattern = re.compile("<HeapMinSize>(.*?)</HeapMinSize>")

    heap_max_size = ""
    heap_init_size = ""
    heap_min_size = ""

    configure_file = open(configure_file_name)
    line = configure_file.readline()
    while line:
        # print(line)
        match = heap_max_size_pattern.search(line)
        heap_max_size_tmp = match.group(1) if match else ""
        if len(heap_max_size_tmp) == 0:
            match = heap_init_size_pattern.search(line)
            heap_init_size_tmp = match.group(1) if match else ""
            if len(heap_init_size_tmp) == 0:
                match = heap_min_size_pattern.search(line)
                heap_min_size = match.group(1) if match else heap_min_size
            else:
                heap_init_size = heap_init_size_tmp
        else:
            heap_max_size = heap_max_size_tmp
        line = configure_file.readline()
    configure_file.close()

    # print("heap_max_size=" + heap_max_size)
    # print("heap_init_size=" + heap_init_size)
    # print("heap_min_size=" + heap_min_size)
    heap_size = ""
    if len(heap_init_size) != 0:
        heap_size = heap_init_size
    elif len(heap_max_size) != 0:
        heap_size = heap_max_size
    elif len(heap_min_size) != 0:
        heap_size = heap_min_size
    else:
        heap_size = "0"
    # print("heap_size=" + heap_size)

    os.system("sed -ri 's@#define ENCLAVE_HEAP_SIZE(.*)@#define ENCLAVE_HEAP_SIZE " +
              heap_size + "@' SGXSanManifest.h")
