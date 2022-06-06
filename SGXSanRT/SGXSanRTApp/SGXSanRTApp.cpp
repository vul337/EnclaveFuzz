#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <array>
#include <memory>
#include <iostream>
#include <unistd.h>
#include <regex>
#include <unistd.h>

#include "SGXSanManifest.h"
#include "SGXSanRTUBridge.hpp"
#include "SGXSanCommonShadowMap.hpp"
#include "SGXSanCommonPoison.hpp"
#include "SGXSanDefs.h"
#include "SGXSanLog.hpp"

struct SGXSanMMapInfo
{
	uint64_t start = 0;
	uint64_t end = 0;
	bool is_readable = false;
	bool is_writable = false;
	bool is_executable = false;
	bool is_shared = false;
	bool is_private = false;
};

// pass string to ENCLAVE_FILENAME (https://stackoverflow.com/questions/54602025/how-to-pass-a-string-from-a-make-file-into-a-c-program)
#define _xstr(s) _str(s)
#define _str(s) #s
std::string enclave_name(_xstr(ENCLAVE_FILENAME));

uptr g_enclave_base = 0, g_enclave_size = 0;
uint64_t kLowMemBeg = 0, kLowMemEnd = 0,
		 kLowShadowBeg = 0, kLowShadowEnd = 0,
		 kShadowGapBeg = 0, kShadowGapEnd = 0,
		 kHighShadowBeg = 0, kHighShadowEnd = 0,
		 kHighMemBeg = 0, kHighMemEnd = 0;
static uint64_t g_enclave_low_guard_start = 0, g_enclave_high_guard_end = 0;
static struct sigaction g_old_sigact[_NSIG];
std::string sgxsan_exec(const char *cmd);

static const char *log_level_to_prefix[] = {
	[LOG_LEVEL_NONE] = "",
	[LOG_LEVEL_ERROR] = "[SGXSan error] ",
	[LOG_LEVEL_WARNING] = "[SGXSan warning] ",
	[LOG_LEVEL_DEBUG] = "[SGXSan debug] ",
	[LOG_LEVEL_TRACE] = "[SGXSan trace] ",
};

void sgxsan_log(log_level ll, bool with_prefix, const char *fmt, ...)
{
	if (ll > USED_LOG_LEVEL)
		return;

	char buf[BUFSIZ] = {'\0'};
	std::string prefix = "";
	if (with_prefix)
	{
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

	printf("%s", content.c_str());
}

void PrintAddressSpaceLayout()
{
	log_debug("|| `[%16p, %16p]` || Shadow    ||\n", (void *)kLowShadowBeg, (void *)kLowShadowEnd);
	log_debug("|| `[%16p, %16p]` || LowGuard  ||\n", (void *)g_enclave_low_guard_start, (void *)(g_enclave_base - 1));
	log_debug("|| `[%16p, %16p]` || Elrange   ||\n", (void *)g_enclave_base, (void *)(g_enclave_base + g_enclave_size - 1));
	log_debug("|| `[%16p, %16p]` || HighGuard ||\n\n", (void *)(g_enclave_base + g_enclave_size), (void *)g_enclave_high_guard_end);
}

void sgxsan_sigaction(int signum, siginfo_t *siginfo, void *priv)
{
	if (signum == SIGSEGV)
	{
		// process siginfo
		uint64_t page_fault_addr = (uint64_t)siginfo->si_addr;
		if ((void *)page_fault_addr == nullptr)
		{
			log_error("Null-Pointer dereference\n");
		}
		else if ((g_enclave_low_guard_start <= page_fault_addr && page_fault_addr < g_enclave_base) ||
				 ((g_enclave_base + g_enclave_size) <= page_fault_addr && page_fault_addr <= g_enclave_high_guard_end))
		{
			log_error("Pointer dereference overflows enclave boundray (Overlapping memory access)\n");
		}
		else if ((g_enclave_base + g_enclave_size - 0x1000) <= page_fault_addr && page_fault_addr < (g_enclave_base + g_enclave_size))
		{
			log_error("Infer pointer dereference overflows enclave boundray, as mprotect's effort is page-granularity and si_addr only give page-granularity address\n");
		}
	}

	// call previous signal handler
	if (SIG_DFL == g_old_sigact[signum].sa_handler)
	{
		signal(signum, SIG_DFL);
		raise(signum);
	}
	// if there is old signal handler, we need transfer the signal to the old signal handler;
	else
	{
		// make sure signum to be masked if SA_NODEFER is not set
		if (!(g_old_sigact[signum].sa_flags & SA_NODEFER))
			sigaddset(&g_old_sigact[signum].sa_mask, signum);
		// use mask of old sigact
		sigset_t cur_set;
		pthread_sigmask(SIG_SETMASK, &g_old_sigact[signum].sa_mask, &cur_set);

		if (g_old_sigact[signum].sa_flags & SA_SIGINFO)
		{
			g_old_sigact[signum].sa_sigaction(signum, siginfo, priv);
		}
		else
		{
			g_old_sigact[signum].sa_handler(signum);
		}

		pthread_sigmask(SIG_SETMASK, &cur_set, NULL);

		// If the g_old_sigact set SA_RESETHAND, it will break the chain which means
		// g_old_sigact->next_old_sigact will not be called. Our signal handler does not
		// responsable for that. We just follow what os do on SA_RESETHAND.
		if (g_old_sigact[signum].sa_flags & SA_RESETHAND)
			g_old_sigact[signum].sa_handler = SIG_DFL;
	}
}

void reg_sgxsan_sigaction()
{
	struct sigaction sig_act;
	memset(&sig_act, 0, sizeof(sig_act));
	sig_act.sa_sigaction = sgxsan_sigaction;
	sig_act.sa_flags = SA_SIGINFO | SA_NODEFER | SA_RESTART;
	sigemptyset(&sig_act.sa_mask);
	sgxsan_error(0 != sigprocmask(SIG_SETMASK, NULL, &sig_act.sa_mask), "Fail to get signal mask\n");
	// make sure SIGSEGV is not blocked
	sigdelset(&sig_act.sa_mask, SIGSEGV);
	// take place before signal handler of sgx aex
	sgxsan_error(0 != sigaction(SIGSEGV, &sig_act, &g_old_sigact[SIGSEGV]), "Fail to regist SIGSEGV action\n");
}

// create shadow memory outside enclave for elrange
// because shadow is independent of elrange, we just need one block of memory for shadow, and don't need consider shadow gap.
void sgxsan_ocall_init_shadow_memory(uptr enclave_base, uptr enclave_size, uptr *shadow_beg_ptr, uptr *shadow_end_ptr)
{
	g_enclave_base = enclave_base;
	g_enclave_size = enclave_size;

	// only use LowMem and LowShadow as ELRANGE and EnclaveShadow
	kLowShadowBeg = SGXSAN_SHADOW_MAP_BASE;
	kLowShadowEnd = (enclave_size >> 3) + kLowShadowBeg - 1;
	kLowMemBeg = g_enclave_base;
	kLowMemEnd = g_enclave_base + enclave_size - 1;

	uptr shadow_start = kLowShadowBeg;

	uptr page_size = getpagesize();
	sgxsan_error(page_size != 0x1000, "Currently only support 4k page size\n");
	shadow_start -= page_size;

	// fix-me: may need unmap at destructor
	// mmap the shadow plus at least one page at the left.
	sgxsan_error((MAP_FAILED == mmap((void *)shadow_start, kLowShadowEnd - shadow_start + 1,
									 PROT_READ | PROT_WRITE,
									 MAP_PRIVATE | MAP_FIXED | MAP_NORESERVE | MAP_ANON,
									 -1, 0)) ||
					 (-1 == madvise((void *)shadow_start, kLowShadowEnd - shadow_start + 1, MADV_NOHUGEPAGE)),
				 "Shadow Memory unavailable\n");

	sgxsan_error(((kLowMemBeg & 0xfff) != 0) ||
					 (((kLowMemEnd + 1) & 0xfff) != 0),
				 "Elrange is not aligned to page\n");

	// consistent with modification in psw/enclave_common/sgx_enclave_common.cpp:enclave_create_ex
	g_enclave_low_guard_start = kLowMemBeg - page_size;
	g_enclave_high_guard_end = kLowMemEnd + page_size;

	// make sure 0 address is not accessible
	auto result = sgxsan_exec("sysctl vm.mmap_min_addr");
	std::regex mmap_min_addr_patten("vm.mmap_min_addr = ([0-9a-fA-F]+)");
	std::smatch match;
	if (std::regex_search(result, match, mmap_min_addr_patten))
	{
		auto mmap_min_addr_str = match[1].str();
		auto mmap_min_addr = std::stoll(mmap_min_addr_str, nullptr, 0);
		if (mmap_min_addr == 0)
			sgxsan_error(MAP_FAILED == mmap((void *)0, 0x10000,
											PROT_NONE,
											MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
											-1, 0),
						 "Failed to make 0 address not accessible\n");
	}

	PrintAddressSpaceLayout();

	*shadow_beg_ptr = kLowShadowBeg;
	*shadow_end_ptr = kLowShadowEnd;

	reg_sgxsan_sigaction();
}

/* OCall functions */
void sgxsan_ocall_print_string(const char *str)
{
	/* Proxy/Bridge will check the length and null-terminate
	 * the input string to prevent buffer overflow.
	 */
	std::cerr << str;
}

// from (https://stackoverflow.com/questions/478898/how-do-i-execute-a-command-and-get-the-output-of-the-command-within-c-using-po)
std::string sgxsan_exec(const char *cmd)
{
	std::array<char, 128> buffer;
	std::string result;
	std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
	if (!pipe)
	{
		throw std::runtime_error("popen() failed!");
	}
	while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
	{
		result += buffer.data();
	}
	return result;
}

std::string addr2line(uint64_t addr)
{
	std::stringstream cmd;
	cmd << "addr2line -afCpe " << enclave_name.c_str() << " " << std::hex << addr;
	std::string cmd_str = cmd.str();
	return sgxsan_exec(cmd_str.c_str());
}

void string_rtrim(std::string &str)
{
	str.erase(std::find_if(str.rbegin(), str.rend(), [](unsigned char ch)
						   { return !std::isspace(ch); })
				  .base(),
			  str.end());
}

std::string addr2func_name(uint64_t addr)
{
	std::stringstream cmd;
	cmd << "addr2line -afCpe " << enclave_name.c_str() << " " << std::hex << addr << "|cut -d \" \" -f 2";
	std::string cmd_str = cmd.str(), ret_str = sgxsan_exec(cmd_str.c_str());
	string_rtrim(ret_str);
	return ret_str;
}

void sgxsan_ocall_addr2func_name(uint64_t addr, char *func_name, size_t buf_size)
{
	std::string str = addr2func_name(addr);
	size_t cp_size = std::min(buf_size - 1, str.length());
	strncpy(func_name, str.c_str(), cp_size);
	func_name[cp_size] = '\0';
}

void sgxsan_ocall_addr2line(uint64_t addr, int level)
{
	std::cerr << "    #" << level << " " << addr2line(addr);
}

void sgxsan_ocall_addr2line_ex(uint64_t *addr_arr, size_t arr_cnt, int level)
{
	(void)level;
	for (size_t i = 0; i < arr_cnt; i++)
	{
		sgxsan_ocall_addr2line(addr_arr[i], (int)i);
	}
}

void sgxsan_ocall_depcit_distribute(uint64_t addr, unsigned char *byte_arr, size_t byte_arr_size, int bucket_num, bool is_cipher)
{
	static int prefix = 0;
	std::string func_name = addr2func_name(addr), byte_str = "[", dir = "sgxsan_data_" + std::to_string(getpid());
	for (size_t i = 0; i < byte_arr_size; i++)
	{
		byte_str = byte_str + std::to_string(byte_arr[i]) + (i == byte_arr_size - 1 ? "]" : ",");
	}

	mkdir(dir.c_str(), 0777);
	std::string save_fname = dir + "/" + std::to_string(prefix++) + "_" + func_name + (is_cipher ? "_true" : "_false") + ".json";
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

void sgxsan_ocall_get_mmap_infos(void *mmap_infos, size_t max_size, size_t *real_cnt)
{
	SGXSanMMapInfo *infos = (SGXSanMMapInfo *)mmap_infos;
	size_t max_cnt = max_size / sizeof(SGXSanMMapInfo);
	assert(max_size % sizeof(SGXSanMMapInfo) == 0);

	std::fstream f("/proc/self/maps", std::ios::in);
	std::string line;
	size_t cnt = 0;
	while (std::getline(f, line) && cnt < max_cnt)
	{
		std::regex map_pattern("([0-9a-fA-F]*)-([0-9a-fA-F]*) ([r-])([w-])([x-])([ps-])(.*)");
		std::smatch match;
		if (std::regex_search(line, match, map_pattern))
		{
			try
			{
				SGXSanMMapInfo &info = infos[cnt];
				info.start = std::stoll(match[1].str(), nullptr, 16);
				info.end = std::stoll(match[2].str(), nullptr, 16) - 1;
				info.is_readable = match[3] == "r";
				info.is_writable = match[4] == "w";
				info.is_executable = match[5] == "x";
				info.is_shared = match[6] == "s";
				info.is_private = match[6] == "p";
				// std::string remained = match[7];
				// std::regex remained_pattern("([0-9a-fA-F]*)[ ]+([0-9a-fA-F]*):([0-9a-fA-F]*)[ ]+([0-9a-fA-F]*)[ ]+([\\S]*)");
				// std::smatch remained_match;
				// if (std::regex_search(remained, remained_match, remained_pattern))
				// {
				// 	auto description = remained_match[5].str();
				// 	auto cpLen = std::min(description.length(), (size_t)63);
				// 	memcpy(info.description, description.c_str(), cpLen);
				// 	info.description[cpLen] = 0;
				// }
				cnt++;
			}
			catch (const std::exception &e)
			{
				// std::cerr << "MMap line can't recognize:\n\t" << line << "\n";
			}
		}
	}

	*real_cnt = cnt;
}
