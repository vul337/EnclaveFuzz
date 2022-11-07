#include "SGXSanRT.h"
#include "ArgShadow.h"
#include "MemAccessMgr.h"
#include "plthook.h"
#include <execinfo.h>
#include <fstream>
#include <iostream>
#include <pthread.h>
#include <regex>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>

enum EncryptStatus { Unknown, Plaintext, Ciphertext };

static const char *log_level_to_prefix[] = {
    [LOG_LEVEL_ALWAYS] = "",
    [LOG_LEVEL_ERROR] = "[SGXSan error] ",
    [LOG_LEVEL_WARNING] = "[SGXSan warning] ",
    [LOG_LEVEL_DEBUG] = "[SGXSan debug] ",
    [LOG_LEVEL_TRACE] = "[SGXSan trace] ",
};

bool asan_inited = false;

std::unordered_map<void * /* callsite addr */,
                   std::vector<EncryptStatus> /* output type history */>
    output_history;
static pthread_rwlock_t output_history_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static struct sigaction g_old_sigact[_NSIG];

static std::string sgxsan_exec(const char *cmd) {
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

static void PrintAddressSpaceLayout() {
  log_debug("|| `[%16p, %16p]` || LowMem          ||\n", (void *)kLowMemBeg,
            (void *)kLowMemEnd);
  log_debug("|| `[%16p, %16p]` || LowShadowGuard  ||\n",
            (void *)kLowShadowGuardBeg, (void *)(kLowShadowBeg - 1));
  log_debug("|| `[%16p, %16p]` || LowShadow       ||\n", (void *)kLowShadowBeg,
            (void *)kLowShadowEnd);
  log_debug("|| `[%16p, %16p]` || ShadowGap       ||\n", (void *)kShadowGapBeg,
            (void *)kShadowGapEnd);
  log_debug("|| `[%16p, %16p]` || HighShadow      ||\n", (void *)kHighShadowBeg,
            (void *)kHighShadowEnd);
  log_debug("|| `[%16p, %16p]` || HighShadowGuard ||\n",
            (void *)(kHighShadowEnd + 1), (void *)kHighShadowGuardEnd);
  log_debug("|| `[%16p, %16p]` || HighMem         ||\n", (void *)kHighMemBeg,
            (void *)kHighMemEnd);
}

/// \brief Signal handler to report illegal memory access
static void sgxsan_sigaction(int signum, siginfo_t *siginfo, void *priv) {
  size_t page_size = getpagesize();
  // process siginfo
  void *_page_fault_addr = siginfo->si_addr;
  log_error("#PF Addr: %p\n", _page_fault_addr);
  uint64_t page_fault_addr = (uint64_t)_page_fault_addr;
  if (page_fault_addr == 0) {
    log_error("Null-Pointer Dereference\n");
  } else if ((kLowShadowGuardBeg <= page_fault_addr &&
              page_fault_addr < kLowShadowBeg) ||
             (kHighShadowEnd < page_fault_addr &&
              page_fault_addr <= kHighShadowGuardEnd)) {
    log_error("ShadowMap's Guard Dereference\n");
  } else if ((kHighShadowEnd + 1 - page_size) <= page_fault_addr &&
             page_fault_addr <= kHighShadowEnd) {
    log_error("Cross ShadowMap's Guard Dereference\n");
  } else if (kShadowGapBeg <= page_fault_addr &&
             page_fault_addr < kShadowGapEnd) {
    log_error("ShadowMap's GAP Dereference\n");
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

static void register_sgxsan_sigaction() {
  struct sigaction sig_act;
  memset(&sig_act, 0, sizeof(sig_act));
  sig_act.sa_sigaction = sgxsan_sigaction;
  sig_act.sa_flags = SA_SIGINFO | SA_NODEFER | SA_RESTART;
  sigemptyset(&sig_act.sa_mask);
  sgxsan_error(0 != sigprocmask(SIG_SETMASK, NULL, &sig_act.sa_mask),
               "Fail to get signal mask\n");
  // make sure SIGSEGV is not blocked
  sigdelset(&sig_act.sa_mask, SIGSEGV);
  // hool SIGSEGV
  sgxsan_error(0 != sigaction(SIGSEGV, &sig_act, &g_old_sigact[SIGSEGV]),
               "Fail to regist SIGSEGV action\n");
}

/// \brief Initialize shadow memory
static void sgxsan_init_shadow_memory() {
  size_t page_size = getpagesize();
  sgxsan_assert(page_size == PAGE_SIZE);

  // mmap the shadow plus it's guard pages
  sgxsan_error(mmap((void *)kLowShadowGuardBeg,
                    kHighShadowGuardEnd - kLowShadowGuardBeg + 1,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_FIXED | MAP_NORESERVE | MAP_ANON, -1,
                    0) == MAP_FAILED,
               "Shadow Memory is not available\n");
  sgxsan_error(madvise((void *)kLowShadowGuardBeg,
                       kHighShadowGuardEnd - kLowShadowGuardBeg + 1,
                       MADV_NOHUGEPAGE) == -1,
               "Fail to madvise MADV_NOHUGEPAGE\n");
  sgxsan_error(mprotect((void *)kLowShadowGuardBeg, page_size, PROT_NONE) ||
                   mprotect((void *)(kHighShadowEnd + 1), page_size, PROT_NONE),
               "Failed to make guard page for shadow map\n");
  sgxsan_error(mprotect((void *)kShadowGapBeg,
                        kShadowGapEnd - kShadowGapBeg + 1, PROT_NONE),
               "Failed to make gap in shadow not accessible\n");

  // make sure 0 address is not accessible
  auto mmap_min_addr = std::stoull(
      sgxsan_exec("sysctl vm.mmap_min_addr| tr -s ' '|cut -d \" \" -f3"),
      nullptr, 0);
  if (mmap_min_addr == 0) {
    mmap((void *)0, page_size, PROT_NONE,
         MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    sgxsan_error(mprotect((void *)0, page_size, PROT_NONE),
                 "Failed to make 0 address not accessible\n");
  }
}

DEFINE_FUNC_PTR(malloc);
DEFINE_FUNC_PTR(free);
DEFINE_FUNC_PTR(calloc);
DEFINE_FUNC_PTR(realloc);
DEFINE_FUNC_PTR(malloc_usable_size);

int hook_libstdcxx_heap_mgr() {
  plthook_t *plthook;

  if (plthook_open(&plthook, "libstdc++.so.6") != 0) {
    log_error("plthook_open error: %s\n", plthook_error());
    return -1;
  }
  /// \c calloc and \c malloc_usable_size is not used by
  /// \file /lib/x86_64-linux-gnu/libstdc++.so.6
  if (plthook_replace(plthook, "malloc", (void *)malloc, NULL) != 0 ||
      plthook_replace(plthook, "free", (void *)free, NULL) != 0 ||
      plthook_replace(plthook, "realloc", (void *)realloc, NULL) != 0) {
    log_error("plthook_replace error: %s\n", plthook_error());
    plthook_close(plthook);
    return -1;
  }
  plthook_close(plthook);
  return 0;
}

static void get_real_heap_allocator() {
  GET_REAL_FUNC(malloc);
  GET_REAL_FUNC(free);
  GET_REAL_FUNC(calloc);
  GET_REAL_FUNC(realloc);
  GET_REAL_FUNC(malloc_usable_size);
}

static void AsanInitInternal() {
  if (LIKELY(asan_inited))
    return;
  // make sure c++ stream is initialized
  std::ios_base::Init _init;
  sgxsan_init_shadow_memory();
  PrintAddressSpaceLayout();
  register_sgxsan_sigaction();
  get_real_heap_allocator();
  if (hook_libstdcxx_heap_mgr() != 0) {
    abort();
  }
  asan_inited = true;
}

extern "C" void __asan_init() { AsanInitInternal(); }

/// SLSan Callbacks to show dynamic value flow
extern "C" void PrintPtr(char *info, void *addr, size_t size) {
  sgxsan_assert(addr and size);
  log_trace("%s\n"
            "Address: 0x%p(0x%lx)\n"
            "Shadow: 0x%p(0x%lx)\n",
            info, addr, size, (void *)MEM_TO_SHADOW(addr),
            RoundUpDiv(size, SHADOW_GRANULARITY));
}

/// \param func_ptr address of function
/// \param pos -1 means it's return value of \p func_ptr
extern "C" void PrintArg(char *info, void *func_ptr, int pos) {
  log_trace("%s\n"
            "Function: 0x%p\n"
            "ArgIdx: %ld\n",
            info, func_ptr, pos);
}

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

static void PrintShadowMap(log_level ll, uptr addr) {
  uptr shadowAddr = MEM_TO_SHADOW(addr);
  uptr shadowAddrRow = RoundDownTo(shadowAddr, 0x10);
  int shadowAddrCol = (int)(shadowAddr - shadowAddrRow);
  char buf[BUFSIZ];
  snprintf(buf, BUFSIZ, "Shadow bytes around the buggy address:\n");
  std::string str = buf;
  for (int i = 0; i <= 10; i++) {
    snprintf(buf, BUFSIZ, "%s%p:", i == 5 ? "=>" : "  ",
             (void *)(shadowAddrRow - 0x50 + 0x10 * i));
    str += buf;
    for (int j = 0; j < 16; j++) {
      std::string prefix = " ", appendix = "";
      if (i == 5) {
        if (j == shadowAddrCol) {
          prefix = "[";
          if (shadowAddrCol == 15) {
            appendix = "]";
          }
        } else if (j == shadowAddrCol + 1)
          prefix = "]";
      }
      snprintf(buf, BUFSIZ, "%s%02x%s", prefix.c_str(),
               *(uint8_t *)(shadowAddrRow - 0x50 + 0x10 * i + j),
               appendix.c_str());
      str += buf;
    }
    str += " \n";
  }
  str +=
      "Shadow byte legend (one shadow byte represents 8 application bytes):\n"
      "  Addressable:           00\n"
      "  Partially addressable: 01 02 03 04 05 06 07\n"
      "  SGX sensitive layout:  1X\n"
      "  SGX sensitive data:    2X\n"
      "  Data in Enclave:       4X\n"
      "  Stack left redzone:    81\n"
      "  Stack mid redzone:     82\n"
      "  Stack right redzone:   83\n"
      "  Stack after return:    85\n"
      "  Left alloca redzone:   86\n"
      "  Right alloca redzone:  87\n"
      "  Stack use after scope: 88\n"
      "  Global redzone:        89\n"
      "  Heap left redzone:     8a\n"
      "  Heap righ redzone:     8b\n"
      "  Freed Heap region:     8d\n"
      "  ASan internal:         8e\n";
  sgxsan_log(ll, false, str.c_str());
}

void ReportGenericError(uptr pc, uptr bp, uptr sp, uptr addr, bool is_write,
                        uptr access_size, bool fatal, const char *msg) {
  log_level ll = fatal ? LOG_LEVEL_ERROR : LOG_LEVEL_WARNING;
  sgxsan_log(ll, false,
             "================ Error Report ================\n"
             "%s\n"
             "  pc = 0x%lx\tbp   = 0x%lx\n"
             "  sp = 0x%lx\taddr = 0x%lx\n"
             "  is_write = %d\t\taccess_size = 0x%lx\n",
             msg, pc, bp, sp, addr, is_write, access_size);
  sgxsan_backtrace(ll);
  PrintShadowMap(ll, addr);
  sgxsan_log(ll, false, "================= Report End =================\n");
  if (fatal)
    abort();
  return;
}

std::string addr2line(uptr addr, std::string fileName) {
  std::stringstream cmd;
  cmd << "addr2line -afCpe " << fileName.c_str() << " " << std::hex << addr;
  std::string cmd_str = cmd.str();
  return sgxsan_exec(cmd_str.c_str());
}

std::string addr2line_fname(uptr addr, std::string fileName) {
  std::stringstream cmd;
  cmd << "addr2line -fCe " << fileName.c_str() << " " << std::hex << addr
      << " | head -n 1";
  std::string cmd_str = cmd.str();
  return sgxsan_exec(cmd_str.c_str());
}

void sgxsan_backtrace(log_level ll) {
#if (DUMP_STACK_TRACE)
  if (ll > USED_LOG_LEVEL)
    return;
  void *array[20];
  size_t size = backtrace(array, 20);
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
#endif
}

static void *sgxsan_backtrace_i(int idx) {
  void *array[idx + 1];
  int size = backtrace(array, idx + 1);
  sgxsan_assert(size == idx + 1);
  return array[idx];
}

/// Cipher detect
static inline int getBucketNum(size_t size) {
  return size >= 0x800   ? 0x100
         : size >= 0x100 ? 0x40
         : size >= 0x10  ? 0x4
         : size >= 0x2   ? 0x2
                         : 0x1;
}

static EncryptStatus isCiphertext(uint64_t addr, uint64_t size) {
  if (size < 0x100)
    return Unknown;

  int bucket_num = getBucketNum(size);

  int map[256 /* 2^8 */] = {0};

  // collect byte map
  for (uint64_t i = 0; i < size; i++) {
    unsigned char byte = *(unsigned char *)(addr + i);
    map[byte]++;
  }

  double CountPerBacket = (int)size / (double)bucket_num;
  if (size >= 0x100)
    CountPerBacket = (int)(size - map[0] /* maybe 0-padding in ciphertext */) /
                     (double)(bucket_num - 1);

  bool is_cipher = true;
  int step = 0x100 / bucket_num;
  log_trace("[Cipher Detect] CountPerBacket = %f \n", CountPerBacket);

  for (int i = 0; i < 256; i += step) {
    int sum = getArraySum(map + i, step);
    if ((sum > CountPerBacket * 1.5 || sum < CountPerBacket / 2) and
        (size >= 0x100 ? i != 0 : true)) {
      is_cipher = false;
      break;
    }
  }

  if (!is_cipher) {
    Dl_info info;
    void *addr = sgxsan_backtrace_i(4);
    if (dladdr(addr, &info) != 0) {
      auto fname = addr2line_fname(
          (uptr)addr -
              ((uptr)info.dli_fbase == 0x400000 ? 0 : (uptr)info.dli_fbase) - 1,
          info.dli_fname);
      fname.erase(std::remove(fname.begin(), fname.end(), '\n'), fname.end());
      log_warning("[%s] Plaintext transfering...\n", fname.c_str());
    }
  }
  return is_cipher ? Ciphertext : Plaintext;
}

void check_output_hybrid(uint64_t addr, uint64_t size) {
  pthread_rwlock_wrlock(&output_history_rwlock);

  // get history of callsite
  std::vector<EncryptStatus> &history =
      output_history[(void *)((uptr)sgxsan_backtrace_i(3) - 1)];

  EncryptStatus status = isCiphertext(addr, size);
  if (history.size() == 0) {
    history.emplace_back(status);
  } else {
    EncryptStatus last_known_status = Unknown;
    for (auto it = history.rbegin(); it != history.rend(); it++) {
      if (*it != Unknown) {
        last_known_status = *it;
        break;
      }
    }
    history.emplace_back(status);

    sgxsan_warning(last_known_status != Unknown && status != Unknown &&
                       last_known_status != status,
                   "Output is plaintext ciphertext hybridization\n");
  }
  pthread_rwlock_unlock(&output_history_rwlock);
}

static __thread int TD_init_count = 0;

extern "C" void TDECallConstructor() {
  if (TD_init_count == 0) {
    // root ecall
    MemAccessMgr::init();
    ArgShadowStack::init();
  }
  TD_init_count++;
  sgxsan_assert(TD_init_count < 1024);
}

extern "C" void TDECallDestructor() {
  if (TD_init_count == 1) {
    // root ecall
    MemAccessMgr::destroy();
    ArgShadowStack::destroy();
  }
  TD_init_count--;
  sgxsan_assert(TD_init_count >= 0);
}

extern "C" void SGXSanTDECallEmergencyDestructor() {
  if (TD_init_count > 0) {
    MemAccessMgr::destroy();
    ArgShadowStack::destroy();
    TD_init_count = 0;
  }
}

enum SensitiveDataType { LoadedData = 0, ArgData, ReturnedData };
extern "C" void ReportSensitiveDataLeak(SensitiveDataType srcType,
                                        uptr srcInfo1, uptr srcInfo2,
                                        uptr dstAddr, uptr dstSize) {
  log_warning("Possible leak of sensitive data\n");
  if (srcType == LoadedData) {
    uptr srcAddr = srcInfo1;
    size_t srcSize = srcInfo2;
    GET_CALLER_PC_BP_SP;
    ReportGenericError(pc, bp, sp, srcAddr, false, srcSize, false,
                       "[WARNING] Leak of Sensitive Data");

  } else if (srcType == ArgData or srcType == ReturnedData) {
    sptr argPos = (sptr)srcInfo2;
    uptr funcAddr = srcInfo1;
    log_warning("Src info: Arg %ld of func at 0x%lx\n", argPos, funcAddr);
  } else {
    abort();
  }
  log_warning("Dst info: 0x%lx(0x%lx)\n", dstAddr, dstSize);
}
