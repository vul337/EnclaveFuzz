#include <algorithm>
#include <array>
#include <assert.h>
#include <errno.h>
#include <fstream>
#include <iostream>
#include <memory>
#include <regex>
#include <signal.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "SGXSanCommonPoison.hpp"
#include "SGXSanCommonShadowMap.hpp"
#include "SGXSanDefs.h"
#include "SGXSanLog.hpp"
#include "SGXSanManifest.h"
#include "SGXSanRTUBridge.hpp"
#include "config.h"

struct SGXSanMMapInfo {
  uint64_t start = 0;
  uint64_t end = 0;
  bool is_readable = false;
  bool is_writable = false;
  bool is_executable = false;
  bool is_shared = false;
  bool is_private = false;
};

std::string enclave_name(ENCLAVE_FILENAME);

uptr g_enclave_base = 0, g_enclave_size = 0;
uint64_t kEnclaveMemBeg = 0, kEnclaveMemEnd = 0, kEnclaveShadowBeg = 0,
         kEnclaveShadowEnd = 0;
static uint64_t g_enclave_low_guard_start = 0, g_enclave_high_guard_end = 0,
                g_shadow_low_guard_start = 0, g_shadow_high_guard_end = 0;
static struct sigaction g_old_sigact[_NSIG];
// don't touch it at app side, since there is a rwlock applied at enclave side
std::vector<SGXSanMMapInfo> g_mmap_infos;
const bool only_record_readable_mmap_info = true;

std::string sgxsan_exec(const char *cmd);

static const char *log_level_to_prefix[] = {
    "",
    "[SGXSan error] ",
    "[SGXSan warning] ",
    "[SGXSan debug] ",
    "[SGXSan trace] ",
};

void sgxsan_log(log_level ll, bool with_prefix, const char *fmt, ...) {
  if (ll > USED_LOG_LEVEL)
    return;

  char buf[BUFSIZ] = {'\0'};
  std::string prefix = "";
  if (with_prefix) {
#if (SHOW_TID)
    snprintf(buf, BUFSIZ, "[TID=0x%x] ", gettid());
    prefix += buf;
#endif
    prefix += log_level_to_prefix[ll];
  }

  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, BUFSIZ, fmt, ap);
  va_end(ap);
  std::string content = prefix + buf;

  std::cerr << content;
}

void PrintAddressSpaceLayout() {
  log_debug("|| `[%16p, %16p]` || Shadow    ||\n", (void *)kEnclaveShadowBeg,
            (void *)kEnclaveShadowEnd);
  log_debug("|| `[%16p, %16p]` || LowGuard  ||\n",
            (void *)g_enclave_low_guard_start, (void *)(g_enclave_base - 1));
  log_debug("|| `[%16p, %16p]` || Elrange   ||\n", (void *)g_enclave_base,
            (void *)(g_enclave_base + g_enclave_size - 1));
  log_debug("|| `[%16p, %16p]` || HighGuard ||\n\n",
            (void *)(g_enclave_base + g_enclave_size),
            (void *)g_enclave_high_guard_end);
}

void sgxsan_sigaction(int signum, siginfo_t *siginfo, void *priv) {
  if (signum == SIGSEGV) {
    // process siginfo
    void *pf_addr_p = siginfo->si_addr;
    log_error("#PF Addr: %p\n", pf_addr_p);
    uint64_t page_fault_addr = (uint64_t)pf_addr_p;
    if (pf_addr_p == nullptr) {
      log_error("Null-Pointer dereference\n");
    } else if ((g_enclave_low_guard_start <= page_fault_addr &&
                page_fault_addr < g_enclave_base) ||
               ((g_enclave_base + g_enclave_size) <= page_fault_addr &&
                page_fault_addr <= g_enclave_high_guard_end)) {
      log_error("Pointer dereference overflows enclave boundray (Overlapping "
                "memory access)\n");
    } else if ((g_enclave_base + g_enclave_size - 0x1000) <= page_fault_addr &&
               page_fault_addr < (g_enclave_base + g_enclave_size)) {
      log_error("Infer pointer dereference overflows enclave boundray, as "
                "mprotect's effort is page-granularity and si_addr only give "
                "page-granularity address\n");
    } else if ((g_shadow_low_guard_start <= page_fault_addr &&
                page_fault_addr < kEnclaveShadowBeg) ||
               (kEnclaveShadowEnd < page_fault_addr &&
                page_fault_addr <= g_shadow_high_guard_end)) {
      log_error("Pointer dereference overflows shadow map boundray "
                "(Overlapping memory access)\n");
    } else if ((kEnclaveShadowEnd + 1 - 0x1000) <= page_fault_addr &&
               page_fault_addr <= kEnclaveShadowEnd) {
      log_error("Infer pointer dereference overflows shadow map boundray, as "
                "mprotect's effort is page-granularity and si_addr only give "
                "page-granularity address\n");
    }
  }

  // call previous signal handler
  if (SIG_DFL == g_old_sigact[signum].sa_handler) {
    signal(signum, SIG_DFL);
    raise(signum);
  }
  // if there is old signal handler, we need transfer the signal to the old
  // signal handler;
  else {
    // make sure signum to be masked if SA_NODEFER is not set
    if (!(g_old_sigact[signum].sa_flags & SA_NODEFER))
      sigaddset(&g_old_sigact[signum].sa_mask, signum);
    // use mask of old sigact
    sigset_t cur_set;
    pthread_sigmask(SIG_SETMASK, &g_old_sigact[signum].sa_mask, &cur_set);

    if (g_old_sigact[signum].sa_flags & SA_SIGINFO) {
      g_old_sigact[signum].sa_sigaction(signum, siginfo, priv);
    } else {
      g_old_sigact[signum].sa_handler(signum);
    }

    pthread_sigmask(SIG_SETMASK, &cur_set, NULL);

    // If the g_old_sigact set SA_RESETHAND, it will break the chain which means
    // g_old_sigact->next_old_sigact will not be called. Our signal handler does
    // not responsable for that. We just follow what os do on SA_RESETHAND.
    if (g_old_sigact[signum].sa_flags & SA_RESETHAND)
      g_old_sigact[signum].sa_handler = SIG_DFL;
  }
}

void reg_sgxsan_sigaction() {
  struct sigaction sig_act;
  memset(&sig_act, 0, sizeof(sig_act));
  sig_act.sa_sigaction = sgxsan_sigaction;
  sig_act.sa_flags = SA_SIGINFO | SA_NODEFER | SA_RESTART;
  sigemptyset(&sig_act.sa_mask);
  sgxsan_error(0 != sigprocmask(SIG_SETMASK, NULL, &sig_act.sa_mask),
               "Fail to get signal mask\n");
  // make sure SIGSEGV is not blocked
  sigdelset(&sig_act.sa_mask, SIGSEGV);
  // take place before signal handler of sgx aex
  sgxsan_error(0 != sigaction(SIGSEGV, &sig_act, &g_old_sigact[SIGSEGV]),
               "Fail to regist SIGSEGV action\n");
}

static uint8_t *__SGXSanCovMap = (uint8_t *)0x1234567890;
extern "C" void setCovMapAddr(uint8_t *addr) { __SGXSanCovMap = addr; }
extern "C" uint8_t *getCovMapAddr() { return __SGXSanCovMap; }

// create shadow memory outside enclave for elrange
// because shadow is independent of elrange, we just need one block of memory
// for shadow, and don't need consider shadow gap.
void sgxsan_ocall_init_shadow_memory(uptr enclave_base, uptr enclave_size,
                                     uptr *shadow_beg_ptr, uptr *shadow_end_ptr,
                                     uint8_t **cov_map_beg_ptr) {
  *cov_map_beg_ptr = getCovMapAddr();

  g_enclave_base = enclave_base;
  g_enclave_size = enclave_size;

  // only use LowMem and LowShadow as ELRANGE and EnclaveShadow
  kEnclaveShadowBeg = SGXSAN_SHADOW_MAP_BASE;
  kEnclaveShadowEnd = (enclave_size >> 3) + kEnclaveShadowBeg - 1;
  kEnclaveMemBeg = g_enclave_base;
  kEnclaveMemEnd = g_enclave_base + enclave_size - 1;

  uptr page_size = getpagesize();
  sgxsan_error(page_size != 0x1000, "Currently only support 4k page size\n");

  g_shadow_low_guard_start = kEnclaveShadowBeg - page_size;
  g_shadow_high_guard_end = kEnclaveShadowEnd + page_size;

  // fix-me: may need unmap at destructor
  // mmap the shadow plus at least one page at the left.
  sgxsan_error(
      (MAP_FAILED ==
       mmap((void *)g_shadow_low_guard_start,
            g_shadow_high_guard_end - g_shadow_low_guard_start + 1,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_FIXED | MAP_NORESERVE | MAP_ANON, -1, 0)) ||
          (-1 == madvise((void *)g_shadow_low_guard_start,
                         g_shadow_high_guard_end - g_shadow_low_guard_start + 1,
                         MADV_NOHUGEPAGE)),
      "Shadow Memory unavailable\n");
  sgxsan_error(
      mprotect((void *)g_shadow_low_guard_start, page_size, PROT_NONE) ||
          mprotect((void *)(kEnclaveShadowEnd + 1), page_size, PROT_NONE),
      "Failed to make guard page for shadow map");
  sgxsan_error(((kEnclaveMemBeg & 0xfff) != 0) ||
                   (((kEnclaveMemEnd + 1) & 0xfff) != 0),
               "Elrange is not aligned to page\n");

  // consistent with modification in
  // psw/enclave_common/sgx_enclave_common.cpp:enclave_create_ex
  g_enclave_low_guard_start = kEnclaveMemBeg - page_size;
  g_enclave_high_guard_end = kEnclaveMemEnd + page_size;

  // make sure 0 address is not accessible
  auto result = sgxsan_exec("sysctl vm.mmap_min_addr");
  std::regex mmap_min_addr_patten("vm.mmap_min_addr = ([0-9a-fA-F]+)");
  std::smatch match;
  if (std::regex_search(result, match, mmap_min_addr_patten)) {
    auto mmap_min_addr_str = match[1].str();
    auto mmap_min_addr = std::stoull(mmap_min_addr_str, nullptr, 0);
    if (mmap_min_addr == 0)
      sgxsan_error(MAP_FAILED == mmap((void *)0, 0x10000, PROT_NONE,
                                      MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
                                      -1, 0),
                   "Failed to make 0 address not accessible\n");
  }

  PrintAddressSpaceLayout();

  *shadow_beg_ptr = kEnclaveShadowBeg;
  *shadow_end_ptr = kEnclaveShadowEnd;

  reg_sgxsan_sigaction();
}

/* OCall functions */
void sgxsan_ocall_print_string(const char *str) {
  /* Proxy/Bridge will check the length and null-terminate
   * the input string to prevent buffer overflow.
   */
  std::cerr << str;
}

// from
// (https://stackoverflow.com/questions/478898/how-do-i-execute-a-command-and-get-the-output-of-the-command-within-c-using-po)
std::string sgxsan_exec(const char *cmd) {
  std::array<char, 128> buffer;
  std::string result;
  std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
  if (!pipe) {
    throw std::runtime_error("popen() failed!");
  }
  while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
    result += buffer.data();
  }
  return result;
}

std::string addr2line(uint64_t addr) {
  std::stringstream cmd;
  cmd << "addr2line -afCpe " << enclave_name.c_str() << " " << std::hex << addr;
  std::string cmd_str = cmd.str();
  return sgxsan_exec(cmd_str.c_str());
}

std::string addr2func_name(uint64_t addr) {
  auto line = addr2line(addr);
  std::regex line_pattern("(\\S+?):[ ]+(\\S+)[ ]+(\\S+)[ ]+(\\S+)");
  std::smatch match;
  if (std::regex_search(line, match, line_pattern)) {
    return match[2].str();
  }
  return "";
}

void sgxsan_ocall_addr2func_name(uint64_t addr, char *func_name,
                                 size_t buf_size) {
  std::string str = addr2func_name(addr);
  size_t cp_size = std::min(buf_size - 1, str.length());
  strncpy(func_name, str.c_str(), cp_size);
  func_name[cp_size] = '\0';
}

void sgxsan_ocall_addr2line(uint64_t *addr_arr, size_t arr_cnt, int level) {
  (void)level;
  for (size_t i = 0; i < arr_cnt; i++) {
    std::cerr << "    #" << i << " " << addr2line(addr_arr[i]);
  }
}

void sgxsan_ocall_depcit_distribute(uint64_t addr, unsigned char *byte_arr,
                                    size_t byte_arr_size, int bucket_num,
                                    bool is_cipher) {
  static int prefix = 0;
  std::string func_name = addr2func_name(addr), byte_str = "[",
              dir = "sgxsan_data_" + std::to_string(getpid());
  for (size_t i = 0; i < byte_arr_size; i++) {
    byte_str = byte_str + std::to_string(byte_arr[i]) +
               (i == byte_arr_size - 1 ? "]" : ",");
  }

  mkdir(dir.c_str(), 0777);
  std::string save_fname = dir + "/" + std::to_string(prefix++) + "_" +
                           func_name + (is_cipher ? "_true" : "_false") +
                           ".json";
  {
    std::fstream fs(save_fname, fs.out);
    fs << "{\n"
       << "\t\"func_name\": \"" << func_name << "\",\n"
       << "\t\"byte_arr\": " << byte_str << ",\n"
       << "\t\"bucket_num\": " << std::to_string(bucket_num) << ",\n"
       << "\t\"is_cipher\": " << (is_cipher ? "true" : "false") << "\n"
       << "}";
  }
  return;
}

// write lock is applied at enclave side
void sgxsan_ocall_get_mmap_infos(void **mmap_infos, size_t *real_cnt) {
  g_mmap_infos.clear();
  std::fstream f("/proc/self/maps", std::ios::in);
  std::string line;
  std::regex map_pattern(
      "([0-9a-fA-F]*)-([0-9a-fA-F]*) ([r-])([w-])([x-])([ps-])(.*)");
  std::smatch match;
  while (std::getline(f, line)) {
    if (std::regex_search(line, match, map_pattern)) {
      bool is_readable = match[3] == "r";
      if (only_record_readable_mmap_info && !is_readable) {
        continue;
      }
      SGXSanMMapInfo info;
      info.start = std::stoull(match[1].str(), nullptr, 16);
      info.end = std::stoull(match[2].str(), nullptr, 16) - 1;
      info.is_readable = is_readable;
      info.is_writable = match[4] == "w";
      info.is_executable = match[5] == "x";
      info.is_shared = match[6] == "s";
      info.is_private = match[6] == "p";
      // std::string remained = match[7];
      // std::regex remained_pattern("([0-9a-fA-F]*)[
      // ]+([0-9a-fA-F]*):([0-9a-fA-F]*)[ ]+([0-9a-fA-F]*)[ ]+([\\S]*)");
      // std::smatch remained_match;
      // if (std::regex_search(remained, remained_match, remained_pattern))
      // {
      // 	auto description = remained_match[5].str();
      // 	auto cpLen = std::min(description.length(), (size_t)63);
      // 	memcpy(info.description, description.c_str(), cpLen);
      // 	info.description[cpLen] = 0;
      // }
      g_mmap_infos.push_back(info);
    }
  }

  *real_cnt = g_mmap_infos.size();
  *mmap_infos = &g_mmap_infos[0];
}
