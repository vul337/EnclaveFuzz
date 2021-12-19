#pragma once
#include <stdint.h>
#include <stddef.h>

typedef size_t sys_word_t;

typedef struct _thread_data_t
{
    sys_word_t self_addr;
    sys_word_t last_sp;          /* set by urts, relative to TCS */
    sys_word_t stack_base_addr;  /* set by urts, relative to TCS */
    sys_word_t stack_limit_addr; /* set by urts, relative to TCS */
    sys_word_t first_ssa_gpr;    /* set by urts, relative to TCS */
    sys_word_t stack_guard;      /* GCC expects start_guard at 0x14 on x86 and 0x28 on x64 */

    sys_word_t flags;
    sys_word_t xsave_size; /* in bytes (se_ptrace.c needs to know its offset).*/
    sys_word_t last_error; /* init to be 0. Used by trts. */
    struct _thread_data_t *m_next;
    sys_word_t tls_addr;  /* points to TLS pages */
    sys_word_t tls_array; /* points to TD.tls_addr relative to TCS */
    intptr_t exception_flag;
    sys_word_t cxx_thread_info[6];
    sys_word_t stack_commit_addr;
} thread_data_t;

#define REG(name) r##name
#define REGISTER(name) uint64_t REG(name)

/****************************************************************************
 * Definitions for SSA
 ****************************************************************************/
typedef struct _exit_info_t
{
    uint32_t vector : 8;    /* Exception number of exceptions reported inside enclave */
    uint32_t exit_type : 3; /* 3: Hardware exceptions, 6: Software exceptions */
    uint32_t reserved : 20;
    uint32_t valid : 1; /* 0: unsupported exceptions, 1: Supported exceptions */
} exit_info_t;

typedef struct _ssa_gpr_t
{
    REGISTER(ax);          /* (0) */
    REGISTER(cx);          /* (8) */
    REGISTER(dx);          /* (16) */
    REGISTER(bx);          /* (24) */
    REGISTER(sp);          /* (32) */
    REGISTER(bp);          /* (40) */
    REGISTER(si);          /* (48) */
    REGISTER(di);          /* (56) */
    uint64_t r8;           /* (64) */
    uint64_t r9;           /* (72) */
    uint64_t r10;          /* (80) */
    uint64_t r11;          /* (88) */
    uint64_t r12;          /* (96) */
    uint64_t r13;          /* (104) */
    uint64_t r14;          /* (112) */
    uint64_t r15;          /* (120) */
    REGISTER(flags);       /* (128) */
    REGISTER(ip);          /* (136) */
    REGISTER(sp_u);        /* (144) untrusted stack pointer. saved by EENTER */
    REGISTER(bp_u);        /* (152) untrusted frame pointer. saved by EENTER */
    exit_info_t exit_info; /* (160) contain information for exits */
    uint32_t reserved;     /* (164) padding to multiple of 8 bytes */
    uint64_t fs;           /* (168) FS register */
    uint64_t gs;           /* (176) GS register */
} ssa_gpr_t;

#if defined(__cplusplus)
extern "C"
{
#endif
    thread_data_t *get_thread_data(void);
#if defined(__cplusplus)
}
#endif