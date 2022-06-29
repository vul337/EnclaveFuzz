#pragma once
#include <stddef.h>
#include <stdint.h>

// from common/inc/internal/util.h
#define SE_GUARD_PAGE_SHIFT 16
#define SE_GUARD_PAGE_SIZE (1 << SE_GUARD_PAGE_SHIFT)

// from sdk/trts/trts_shared_constants.h
#define STATIC_STACK_SIZE 688

// from sdk/trts/trts_internal.h
#define TD2TCS(td)                                                             \
  ((const void *)(((thread_data_t *)(td))->stack_base_addr +                   \
                  (size_t)STATIC_STACK_SIZE + (size_t)SE_GUARD_PAGE_SIZE))

// from common/inc/internal/thread_data.h
typedef size_t sys_word_t;

typedef struct _thread_data_t {
  sys_word_t self_addr;
  sys_word_t last_sp;          /* set by urts, relative to TCS */
  sys_word_t stack_base_addr;  /* set by urts, relative to TCS */
  sys_word_t stack_limit_addr; /* set by urts, relative to TCS */
  sys_word_t first_ssa_gpr;    /* set by urts, relative to TCS */
  sys_word_t
      stack_guard; /* GCC expects start_guard at 0x14 on x86 and 0x28 on x64 */

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

// from common/inc/internal/se_types.h
#define REG(name) r##name
#define REGISTER(name) uint64_t REG(name)

// from common/inc/internal/arch.h

/****************************************************************************
 * Definitions for SSA
 ****************************************************************************/
typedef struct _exit_info_t {
  uint32_t
      vector : 8; /* Exception number of exceptions reported inside enclave */
  uint32_t exit_type : 3; /* 3: Hardware exceptions, 6: Software exceptions */
  uint32_t reserved : 20;
  uint32_t valid : 1; /* 0: unsupported exceptions, 1: Supported exceptions */
} exit_info_t;

typedef struct _ssa_gpr_t {
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

// from common/inc/internal/metadata.h
typedef uint64_t si_flags_t;

/*
**    layout table example
**    entry0 - entry1 - entry2 - group3 (entry_count=2, load_times=3) ...
**    the load sequence should be:
**    entry0 - entry1 - entry2 - entry1 - entry2 - entry1 - entry2 - entry1 -
*entry2 ...
**                               --------------    -------------- --------------
**                               group3 1st time   group3 2nd time   group3 3rd
*time
*/
typedef struct _layout_entry_t {
  uint16_t id;           /* unique ID to identify the purpose for this entry */
  uint16_t attributes;   /* EADD/EEXTEND/EREMOVE... */
  uint32_t page_count;   /* map size in page. Biggest chunk = 2^32 pages = 2^44
                            bytes. */
  uint64_t rva;          /* map offset, relative to enclave base */
  uint32_t content_size; /* if content_offset = 0, content_size is the initial
                            data to fill the whole page. */
  uint32_t
      content_offset;  /* offset to the initial content, relative to metadata */
  si_flags_t si_flags; /* security info, R/W/X, SECS/TCS/REG/VA */
} layout_entry_t;

typedef struct _layout_group_t {
  uint16_t id;          /* unique ID to identify the purpose for this entry */
  uint16_t entry_count; /* reversely count entry_count entries for the group
                           loading. */
  uint32_t load_times;  /* the repeated times of loading */
  uint64_t load_step;   /* the group size. the entry load rva should be adjusted
                           with the load_step */
                        /* rva = entry.rva + group.load_step * load_times */
  uint32_t reserved[4];
} layout_group_t;

typedef union _layout_t {
  layout_entry_t entry;
  layout_group_t group;
} layout_t;

// layout id
#define GROUP_FLAG (1 << 12)
#define GROUP_ID(x) (GROUP_FLAG | x)
#define IS_GROUP_ID(x) !!((x)&GROUP_FLAG)
#define LAYOUT_ID_HEAP_MIN 1
#define LAYOUT_ID_HEAP_INIT 2
#define LAYOUT_ID_HEAP_MAX 3
#define LAYOUT_ID_TCS 4
#define LAYOUT_ID_TD 5
#define LAYOUT_ID_SSA 6
#define LAYOUT_ID_STACK_MAX 7
#define LAYOUT_ID_STACK_MIN 8
#define LAYOUT_ID_THREAD_GROUP GROUP_ID(9)
#define LAYOUT_ID_GUARD 10
#define LAYOUT_ID_HEAP_DYN_MIN 11
#define LAYOUT_ID_HEAP_DYN_INIT 12
#define LAYOUT_ID_HEAP_DYN_MAX 13
#define LAYOUT_ID_TCS_DYN 14
#define LAYOUT_ID_TD_DYN 15
#define LAYOUT_ID_SSA_DYN 16
#define LAYOUT_ID_STACK_DYN_MAX 17
#define LAYOUT_ID_STACK_DYN_MIN 18
#define LAYOUT_ID_THREAD_GROUP_DYN GROUP_ID(19)
#define LAYOUT_ID_RSRV_MIN (20)
#define LAYOUT_ID_RSRV_INIT (21)
#define LAYOUT_ID_RSRV_MAX (22)

#define TCS_TEMPLATE_SIZE 72

extern const char *layout_id_str[];

// from common/inc/internal/global_data.h
#define LAYOUT_ENTRY_NUM 42
typedef struct _global_data_t {
  sys_word_t sdk_version;
  sys_word_t enclave_size; /* the size of the virtual address range that the
                              enclave will use*/
  sys_word_t heap_offset;
  sys_word_t heap_size;
  sys_word_t rsrv_offset;
  sys_word_t rsrv_size;
  sys_word_t rsrv_executable;
  sys_word_t thread_policy;
  sys_word_t tcs_max_num;
  thread_data_t td_template;
  uint8_t tcs_template[TCS_TEMPLATE_SIZE];
  uint32_t layout_entry_num;
  uint32_t reserved;
  layout_t layout_table[LAYOUT_ENTRY_NUM];
  uint64_t enclave_image_address; /* the base address of the enclave image */
  uint64_t elrange_start_address; /* the base address provided in the enclave's
                                     SECS (SECS.BASEADDR) */
  uint64_t elrange_size; /* the size of the enclave address range provided in
                            the enclave's SECS (SECS.SIZE) */
} global_data_t;

extern global_data_t g_global_data;

// from sdk/trts/init_enclave.cpp
extern uint64_t g_enclave_base, g_enclave_size;

#if defined(__cplusplus)
extern "C" {
#endif
thread_data_t *get_thread_data(void);
size_t get_heap_size(void);
const void *get_tcs(void);
bool is_stack_addr(void *address, size_t size);
#if defined(__cplusplus)
}
#endif