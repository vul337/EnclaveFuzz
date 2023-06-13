#include "SGXSanRTCom.h"
#include "SGXSanRTUBridge.hpp"
#include <algorithm>
#include <array>
#include <assert.h>
#include <boost/stacktrace.hpp>
#include <dlfcn.h>
#include <errno.h>
#include <execinfo.h>
#include <fstream>
#include <iostream>
#include <memory>
#include <regex>
#include <signal.h>
#include <sstream>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

struct SGXSanMMapInfo {
  uint64_t start = 0;
  uint64_t end = 0;
  bool is_readable = false;
  bool is_writable = false;
  bool is_executable = false;
  bool is_shared = false;
  bool is_private = false;
};

uptr g_enclave_base = 0, g_enclave_size = 0;
static uint64_t g_enclave_low_guard_start = 0, g_enclave_high_guard_end = 0;
std::string sgxsan_exec(const char *cmd);

/* Log util */
static const char *log_level_to_prefix[] = {
    "",
    "[SGXSan error] ",
    "[SGXSan warning] ",
    "[SGXSan debug] ",
    "[SGXSan trace] ",
};

extern "C" __attribute__((weak)) void
sgxfuzz_log(log_level ll, bool with_prefix, const char *fmt, ...);
void sgxsan_log(log_level ll, bool with_prefix, const char *fmt, ...) {
  if (sgxfuzz_log) {
    if (with_prefix) {
#if (SHOW_TID)
      sgxfuzz_log(ll, false, "[TID=0x%x] ", gettid());
#endif
      sgxfuzz_log(ll, false, "%s", log_level_to_prefix[ll]);
    }

    char buf[BUFSIZ];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    sgxfuzz_log(ll, false, "%s", buf);
    return;
  }

  if (ll > USED_LOG_LEVEL)
    return;

  if (with_prefix) {
#if (SHOW_TID)
    fprintf(stderr, "[TID=0x%x] ", gettid());
#endif
    fprintf(stderr, "%s", log_level_to_prefix[ll]);
  }

  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
}

void PrintAddressSpaceLayout() {
  log_debug("|| `[%16p, %16p]` || LowMem           ||\n", (void *)kLowMemBeg,
            (void *)kLowMemEnd);
  log_debug("|| `[%16p, %16p]` || LowShadowGuard   ||\n",
            (void *)kLowShadowGuardBeg, (void *)(kLowShadowBeg - 1));
  log_debug("|| `[%16p, %16p]` || LowShadow        ||\n", (void *)kLowShadowBeg,
            (void *)kLowShadowEnd);
  log_debug("|| `[%16p, %16p]` || ShadowGap        ||\n", (void *)kShadowGapBeg,
            (void *)kShadowGapEnd);
  log_debug("|| `[%16p, %16p]` || HighShadow       ||\n",
            (void *)kHighShadowBeg, (void *)kHighShadowEnd);
  log_debug("|| `[%16p, %16p]` || HighShadowGuard  ||\n",
            (void *)(kHighShadowEnd + 1), (void *)kHighShadowGuardEnd);
  log_debug("|| `[%16p, %16p]` || HighMem          ||\n", (void *)kHighMemBeg,
            (void *)kHighMemEnd);
  log_debug("|| `[%16p, %16p]` || LowElrangeGuard  ||\n",
            (void *)g_enclave_low_guard_start, (void *)(g_enclave_base - 1));
  log_debug("|| `[%16p, %16p]` || Elrange          ||\n",
            (void *)g_enclave_base,
            (void *)(g_enclave_base + g_enclave_size - 1));
  log_debug("|| `[%16p, %16p]` || HighElrangeGuard ||\n",
            (void *)(g_enclave_base + g_enclave_size),
            (void *)g_enclave_high_guard_end);
  log_debug("\n");
}

// https://maskray.me/blog/2022-04-10-unwinding-through-signal-handler
void sgxsan_signal_safe_dump_bt_buf(uint64_t *bt_buf, size_t bt_cnt) {
  log_always_np("== SGXSan Backtrace BEG ==\n");
  for (size_t i = 0; i < bt_cnt; i++) {
    uint64_t addr = bt_buf[i];
    Dl_info info;
    if (dladdr((void *)addr, &info) != 0) {
      if (info.dli_saddr) {
        log_always_np("0x%016lx: %s (offset 0x%lx) at %s\n",
                      addr - (uint64_t)info.dli_fbase,
                      info.dli_sname ? info.dli_sname : "?",
                      (uint64_t)info.dli_saddr - (uint64_t)info.dli_fbase,
                      info.dli_fname ? info.dli_fname : "?");
      } else {
        log_always_np("0x%016lx: %s at %s\n", addr - (uint64_t)info.dli_fbase,
                      info.dli_sname ? info.dli_sname : "?",
                      info.dli_fname ? info.dli_fname : "?");
      }
    }
  }
  log_always_np("== SGXSan Backtrace END ==\n");
}

void sgxsan_signal_safe_dump_bt() {
  size_t max_bt_count = 100;
  uint64_t bt_buf[max_bt_count];
  size_t bt_cnt =
      boost::stacktrace::safe_dump_to(bt_buf, sizeof(decltype(bt_buf)));

  sgxsan_signal_safe_dump_bt_buf(bt_buf, bt_cnt);
}
std::string addr2line(uint64_t addr, std::string fileName);
void sgxsan_dump_bt_buf(void **array, size_t size) {
  log_always_np("== SGXSan Backtrace BEG ==\n");
  Dl_info info;
  for (size_t i = 0; i < size; i++) {
    if (dladdr(array[i], &info) != 0) {
      std::string str = addr2line(
          (uptr)array[i] -
              ((uptr)info.dli_fbase == 0x400000 ? 0 : (uptr)info.dli_fbase) - 1,
          info.dli_fname);
      log_always_np(str.c_str());
    }
  }
  log_always_np("== SGXSan Backtrace END ==\n");
}

/* Stack trace */
void sgxsan_print_stack_trace(log_level ll) {
  if (ll > USED_LOG_LEVEL)
    return;
  void *array[20];
  size_t size = backtrace(array, 20);
  sgxsan_dump_bt_buf(array, size);
}

/* Signal */
static struct sigaction g_old_sigact[_NSIG];
#ifdef KAFL_FUZZER
extern "C" {
int DFGetInt32();
__attribute__((weak)) void FuzzerSignalCB(int signum, siginfo_t *siginfo,
                                          void *priv);
__attribute__((weak)) void FuzzerCrashCB();
}
void NORETURN Die() {
  if (FuzzerCrashCB)
    FuzzerCrashCB();
  _Exit(1);
}

void sgxsan_sigaction(int signum, siginfo_t *siginfo, void *priv) {
  ucontext_t *uc = (ucontext_t *)priv;
  const greg_t rip = uc->uc_mcontext.gregs[REG_RIP];
  greg_t *const rip_p = &uc->uc_mcontext.gregs[REG_RIP];
  if (siginfo->si_signo == SIGSEGV) {
    if (siginfo->si_code == SI_KERNEL) {
      // If si_code is SI_KERNEL, #PF address is not true
      log_error("#PF Addr Unknown at pc %p\n", rip);
    } else {
      size_t page_size = getpagesize();
      // process siginfo
      void *_page_fault_addr = siginfo->si_addr;
      log_error("#PF Addr %p at pc %p => ", _page_fault_addr, rip);

      uint64_t page_fault_addr = (uint64_t)_page_fault_addr;
      if (0 <= page_fault_addr and page_fault_addr < page_size) {
        log_error_np("Null-Pointer Dereference\n");
      } else if ((g_enclave_low_guard_start <= page_fault_addr &&
                  page_fault_addr < g_enclave_base) ||
                 ((g_enclave_base + g_enclave_size) <= page_fault_addr &&
                  page_fault_addr <= g_enclave_high_guard_end)) {
        log_error_np(
            "Pointer dereference overflows enclave boundray (Overlapping "
            "memory access)\n");
      } else if ((g_enclave_base + g_enclave_size - 0x1000) <=
                     page_fault_addr &&
                 page_fault_addr < (g_enclave_base + g_enclave_size)) {
        log_error_np(
            "Infer pointer dereference overflows enclave boundray, as "
            "mprotect's effort is page-granularity and si_addr only give "
            "page-granularity address\n");
      } else if ((kLowShadowGuardBeg <= page_fault_addr &&
                  page_fault_addr < kLowShadowBeg) ||
                 (kHighShadowEnd < page_fault_addr &&
                  page_fault_addr <= kHighShadowGuardEnd)) {
        log_error_np("Pointer dereference overflows shadow map boundray "
                     "(Overlapping memory access)\n");
      } else if ((kHighShadowEnd + 1 - page_size) <= page_fault_addr &&
                 page_fault_addr <= kHighShadowEnd) {
        log_error_np(
            "Infer pointer dereference overflows shadow map boundray, as "
            "mprotect's effort is page-granularity and si_addr only give "
            "page-granularity address\n");
      } else if (kShadowGapBeg <= page_fault_addr &&
                 page_fault_addr < kShadowGapEnd) {
        log_error_np("ShadowMap's GAP Dereference\n");
      } else {
        log_error_np("Unknown page fault\n");
      }
    }
  } else if (siginfo->si_signo == SIGILL) {
    if (*(uint32_t *)rip == 0x29ae0f48 /* XRSTOR64 RCX */) {
      *rip_p += 4;
      return;
    } else if ((*(uint32_t *)rip & 0xFFFFFF) == 0xf0c70f /* RDRAND EAX */) {
      uc->uc_mcontext.gregs[REG_RAX] = DFGetInt32();
      uc->uc_mcontext.gregs[REG_EFL] = 1; // CF->1 others->0
      *rip_p += 3;
      return;
    } else if ((*(uint32_t *)rip & 0xFFFFFF) == 0xf6c70f /* RDRAND ESI */) {
      uc->uc_mcontext.gregs[REG_RSI] = DFGetInt32();
      uc->uc_mcontext.gregs[REG_EFL] = 1; // CF->1 others->0
      *rip_p += 3;
      return;
    }
    log_error("SIGILL opcode is %lx\n", *(uint32_t *)rip);
  } else {
    log_error("Signal %d\n", siginfo->si_signo);
  }
  // sgxsan_signal_safe_dump_bt();
  if (FuzzerSignalCB)
    FuzzerSignalCB(signum, siginfo, priv);
  Die();
}
#else
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
    } else if ((kLowShadowGuardBeg <= page_fault_addr &&
                page_fault_addr < kLowShadowBeg) ||
               (kHighShadowEnd < page_fault_addr &&
                page_fault_addr <= kHighShadowGuardEnd)) {
      log_error("Pointer dereference overflows shadow map boundray "
                "(Overlapping memory access)\n");
    } else if ((kHighShadowEnd + 1 - 0x1000) <= page_fault_addr &&
               page_fault_addr <= kHighShadowEnd) {
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
#endif

extern "C" void reg_sgxsan_sigaction() {
  // Register sgxsan_sigaction only once
  static bool HasRegisteredSigaction = false;
  if (HasRegisteredSigaction)
    return;
  HasRegisteredSigaction = true;
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
  sgxsan_assert(0 == sigaction(SIGSEGV, &sig_act, &g_old_sigact[SIGSEGV]));
#ifdef KAFL_FUZZER
  sgxsan_assert(0 == sigaction(SIGFPE, &sig_act, &g_old_sigact[SIGFPE]));
  sgxsan_assert(0 == sigaction(SIGBUS, &sig_act, &g_old_sigact[SIGBUS]));
  sgxsan_assert(0 == sigaction(SIGILL, &sig_act, &g_old_sigact[SIGILL]));
  sgxsan_assert(0 == sigaction(SIGABRT, &sig_act, &g_old_sigact[SIGABRT]));
  sgxsan_assert(0 == sigaction(SIGIOT, &sig_act, &g_old_sigact[SIGIOT]));
  sgxsan_assert(0 == sigaction(SIGTRAP, &sig_act, &g_old_sigact[SIGTRAP]));
  sgxsan_assert(0 == sigaction(SIGSYS, &sig_act, &g_old_sigact[SIGSYS]));
#endif
}

#ifndef KAFL_FUZZER
/* CovMap */
/* Set by pass, get by runtime */
static uint8_t *__SGXSanCovMap = (uint8_t *)0x1234567890;
extern "C" void setCovMapAddr(uint8_t *addr) { __SGXSanCovMap = addr; }
extern "C" uint8_t *getCovMapAddr() { return __SGXSanCovMap; }
#endif

// Memory layout
// ASAN's __asan_init -> __sanitizer_cov_8bit_counters_init ->
// setCovMapAddr -> sgx_create_enclave -> enclave_create_ex -> reg_sig_handler
// -> sgx_ecall -> SGXSan's __asan_init
void sgxsan_ocall_init_shadow_memory(uptr enclave_base, uptr enclave_size,
                                     uint8_t **cov_map_beg_ptr) {
  // Init Enclave info outside Enclave
  g_enclave_base = enclave_base;
  g_enclave_size = enclave_size;

  sgxsan_assert(((g_enclave_base & 0xfff) == 0) &&
                (((g_enclave_base + g_enclave_size) & 0xfff) == 0));

  // Start to init shadow map
  size_t page_size = getpagesize();
  sgxsan_assert(page_size == PAGE_SIZE);

  // consistent with modification in
  // psw/enclave_common/sgx_enclave_common.cpp:enclave_create_ex
  g_enclave_low_guard_start = g_enclave_base - page_size;
  g_enclave_high_guard_end = g_enclave_base + g_enclave_size - 1 + page_size;

#ifndef KAFL_FUZZER
  // get CovMap address if exist
  *cov_map_beg_ptr = getCovMapAddr();
#endif

  // mmap the shadow plus it's guard pages
  sgxsan_assert(mmap((void *)kLowShadowGuardBeg,
                     kHighShadowGuardEnd - kLowShadowGuardBeg + 1,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_FIXED | MAP_NORESERVE | MAP_ANON, -1,
                     0) != MAP_FAILED);
  madvise((void *)kLowShadowGuardBeg,
          kHighShadowGuardEnd - kLowShadowGuardBeg + 1,
          MADV_NOHUGEPAGE); // Return -1 if CONFIG_TRANSPARENT_HUGEPAGE was not
                            // configured in kernel
  sgxsan_assert(
      mprotect((void *)kLowShadowGuardBeg, page_size, PROT_NONE) == 0 &&
      mprotect((void *)(kHighShadowEnd + 1), page_size, PROT_NONE) == 0);
  sgxsan_assert(mprotect((void *)kShadowGapBeg,
                         kShadowGapEnd - kShadowGapBeg + 1, PROT_NONE) == 0);

  // make sure 0 address is not accessible
  auto mmap_min_addr = std::stoull(
      sgxsan_exec("sysctl vm.mmap_min_addr| tr -s ' '|cut -d \" \" -f3"),
      nullptr, 0);
  if (mmap_min_addr == 0) {
    mmap((void *)0, page_size, PROT_NONE,
         MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    sgxsan_assert(mprotect((void *)0, page_size, PROT_NONE) == 0);
  }

  PrintAddressSpaceLayout();

  reg_sgxsan_sigaction();
}

/* OCall functions */
void sgxsan_ocall_print_string(const char *str) {
  /* Proxy/Bridge will check the length and null-terminate
   * the input string to prevent buffer overflow.
   */
  log_always_np("%s", str);
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

/* addr2line */
std::string addr2line(uint64_t addr, std::string fileName) {
  std::stringstream cmd;
  cmd << "addr2line -afCpe " << fileName.c_str() << " " << std::hex << addr;
  std::string cmd_str = cmd.str();
  return sgxsan_exec(cmd_str.c_str());
}

static std::string _addr2fname(uptr addr, std::string fileName) {
  std::stringstream cmd;
  cmd << "addr2line -fCe " << fileName.c_str() << " " << std::hex << addr
      << " | head -n 1";
  std::string cmd_str = cmd.str();
  return sgxsan_exec(cmd_str.c_str());
}

std::string addr2fname(void *addr) {
  std::string fname = "";
  Dl_info info;
  if (dladdr(addr, &info) != 0) {
    fname = _addr2fname(
        (uptr)addr -
            ((uptr)info.dli_fbase == 0x400000 ? 0 : (uptr)info.dli_fbase) - 1,
        info.dli_fname);
    fname.erase(std::remove(fname.begin(), fname.end(), '\n'), fname.end());
  }
  return fname;
}

void sgxsan_ocall_addr2func_name(uint64_t addr, char *func_name,
                                 size_t buf_size) {
  std::string str = addr2fname((void *)addr);
  size_t cp_size = std::min(buf_size - 1, str.length());
  strncpy(func_name, str.c_str(), cp_size);
  func_name[cp_size] = '\0';
}

void sgxsan_ocall_addr2line(uint64_t *addr_arr, size_t arr_cnt, int level) {
  (void)level;
  Dl_info info;
  for (size_t i = 0; i < arr_cnt; i++) {
    if (dladdr((void *)addr_arr[i], &info) != 0) {
      std::string str = addr2line(
          (uptr)addr_arr[i] -
              ((uptr)info.dli_fbase == 0x400000 ? 0 : (uptr)info.dli_fbase) - 1,
          info.dli_fname);
      log_always_np(str.c_str());
    }
  }
}

void sgxsan_ocall_depcit_distribute(uint64_t addr, unsigned char *byte_arr,
                                    size_t byte_arr_size, int bucket_num,
                                    bool is_cipher) {
  static int prefix = 0;
  std::string func_name = addr2fname((void *)addr), byte_str = "[",
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

/* mmap infos */
// don't touch it at app side, since there is a rwlock applied at enclave side
// directly used by Enclave
std::vector<SGXSanMMapInfo> g_mmap_infos;
static const bool only_record_readable_mmap_info = true;
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
