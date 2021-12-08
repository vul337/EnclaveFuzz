#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "SGXSanManifest.h"
#include "SGXSanRTApp.hpp"
#include "SGXSanCommonShadowMap.hpp"
#include "SGXSanCommonPoison.hpp"
#include "SGXSanEnclaveConfigReader.hpp"
#include "SGXSanDefs.h"
#include "PrintfSpeicification.h"

// read ENCLAVE_FILENAME from -DENCLAVE_FILENAME in makefile
#ifndef ENCLAVE_FILENAME
#define ENCLAVE_FILENAME "enclave.signed.so"
#endif
// pass string to ENCLAVE_FILENAME (https://stackoverflow.com/questions/54602025/how-to-pass-a-string-from-a-make-file-into-a-c-program)
#define xstr(s) str(s)
#define str(s) #s

uptr g_enclave_base = 0, g_enclave_size = 0;
uint64_t kLowMemBeg = 0, kLowMemEnd = 0,
		 kLowShadowBeg = 0, kLowShadowEnd = 0,
		 kShadowGapBeg = 0, kShadowGapEnd = 0,
		 kHighShadowBeg = 0, kHighShadowEnd = 0,
		 kHighMemBeg = 0, kHighMemEnd = 0;
static uint64_t g_enclave_low_guard_start = 0, g_enclave_high_guard_end = 0;
static struct sigaction g_old_sigact[_NSIG];
void PrintAddressSpaceLayout()
{
	printf("|| `[%16p, %16p]` || Shadow    ||\n", (void *)kLowShadowBeg, (void *)kLowShadowEnd);
	printf("|| `[%16p, %16p]` || LowGuard  ||\n", (void *)g_enclave_low_guard_start, (void *)(g_enclave_base - 1));
	printf("|| `[%16p, %16p]` || Elrange   ||\n", (void *)g_enclave_base, (void *)(g_enclave_base + g_enclave_size - 1));
	printf("|| `[%16p, %16p]` || HighGuard ||\n\n", (void *)(g_enclave_base + g_enclave_size), (void *)g_enclave_high_guard_end);
}

void sgxsan_sigaction(int signum, siginfo_t *siginfo, void *priv)
{
	ABORT_ASSERT(signum == SIGSEGV, "Currently only regist SIGSEGV handler");

	// process siginfo
	uint64_t page_fault_addr = (uint64_t)siginfo->si_addr;
	if ((void *)page_fault_addr == nullptr)
	{
		printf("[SGXSAN] Null-Pointer dereference\n");
	}
	else if ((g_enclave_low_guard_start <= page_fault_addr && page_fault_addr < g_enclave_base) ||
			 ((g_enclave_base + g_enclave_size) <= page_fault_addr && page_fault_addr <= g_enclave_high_guard_end))
	{
		printf("[SGXSAN] Pointer dereference overflows enclave boundray\n");
	}
	else if ((g_enclave_low_guard_start <= page_fault_addr && page_fault_addr < g_enclave_base) ||
			 ((g_enclave_base + g_enclave_size - 0x1000) <= page_fault_addr && page_fault_addr < (g_enclave_base + g_enclave_size)))
	{
		printf("[SGXSAN] Infer pointer dereference overflows enclave boundray, as mprotect's effort is page-granularity and si_addr only give page-granularity address\n");
	}

	// call previous signal handler
	if (SIG_DFL == g_old_sigact[signum].sa_handler)
	{
		signal(signum, SIG_DFL);
		raise(signum);
	}
	//if there is old signal handler, we need transfer the signal to the old signal handler;
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

		//If the g_old_sigact set SA_RESETHAND, it will break the chain which means
		//g_old_sigact->next_old_sigact will not be called. Our signal handler does not
		//responsable for that. We just follow what os do on SA_RESETHAND.
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
	ABORT_ASSERT(0 == sigprocmask(SIG_SETMASK, NULL, &sig_act.sa_mask), "Fail to get signal mask");
	// make sure SIGSEGV is not blocked
	sigdelset(&sig_act.sa_mask, SIGSEGV);
	// take place before signal handler of sgx aex
	ABORT_ASSERT(0 == sigaction(SIGSEGV, &sig_act, &g_old_sigact[SIGSEGV]), "Fail to regist SIGSEGV action");
}

// create shadow memory outside enclave for elrange
// because shadow is independent of elrange, we just need one block of memory for shadow, and don't need consider shadow gap.
void ocall_init_shadow_memory(uptr enclave_base, uptr enclave_size, uptr *shadow_beg_ptr, uptr *shadow_end_ptr)
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
	ABORT_ASSERT(page_size == 0x1000, "Currently only support 4k page size");
	shadow_start -= page_size;

	// fix-me: may need unmap at destructor
	// mmap the shadow plus at least one page at the left.
	ABORT_ASSERT((MAP_FAILED != mmap((void *)shadow_start, kLowShadowEnd - shadow_start + 1, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_NORESERVE | MAP_ANON, -1, 0)) &&
					 (-1 != madvise((void *)shadow_start, kLowShadowEnd - shadow_start + 1, MADV_NOHUGEPAGE)),
				 "Shadow Memory unavailable");

	ABORT_ASSERT(((kLowMemBeg & 0xfff) == 0) && (((kLowMemEnd + 1) & 0xfff) == 0), "Elrange is not aligned to page");

	// consistent with modification in psw/enclave_common/sgx_enclave_common.cpp:enclave_create_ex
	g_enclave_low_guard_start = kLowMemBeg - page_size;
	g_enclave_high_guard_end = kLowMemEnd + page_size;
	// ABORT_ASSERT((MAP_FAILED != mmap((void *)g_enclave_low_guard_start, kLowMemBeg - g_enclave_low_guard_start, PROT_NONE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)) ||
	//                  (MAP_FAILED != mmap((void *)(kLowMemEnd + 1), g_enclave_high_guard_end - kLowMemEnd, PROT_NONE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)),
	//              "ElrangeGuard unavailable");

	PrintAddressSpaceLayout();

	*shadow_beg_ptr = kLowShadowBeg;
	*shadow_end_ptr = kLowShadowEnd;

	// start shallow poison on sensitive layout
	SGXSanEnclaveConfigReader reader{g_enclave_base};
	// printf("ENCLAVE_FILENAME=%s\n", xstr(ENCLAVE_FILENAME));
	reader.collect_layout_infos(xstr(ENCLAVE_FILENAME));
	reader.shallow_poison_senitive();

	// memset((void *)(kLowShadowBeg - page_size), kSGXSanElrangeLeftGuard, page_size);

	reg_sgxsan_sigaction();
}

/* OCall functions */
extern "C" void sgxsan_ocall_print_string(const char *str)
{
	/* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
	printf("%s", str);
}
