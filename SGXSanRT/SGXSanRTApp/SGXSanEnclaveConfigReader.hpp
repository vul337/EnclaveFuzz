#ifndef SGXSAN_ENCLAVE_CONFIG_READER
#define SGXSAN_ENCLAVE_CONFIG_READER

#include <stdint.h>
#include <elf.h>
#include <vector>

/** the callback function to filter a section.
 *
 * @shstrtab:  the section header string table
 * @shdr:      the current section header to be examined
 * @user_data: user supplied data for the callback
 *
 * @return: true if current section header is what we are looking for.
 */
typedef bool (*section_filter_f)(const char *shstrtab,
                                 const Elf64_Shdr *shdr,
                                 const void *user_data);

typedef uint64_t si_flags_t;

/*
**    layout table example
**    entry0 - entry1 - entry2 - group3 (entry_count=2, load_times=3) ...
**    the load sequence should be:
**    entry0 - entry1 - entry2 - entry1 - entry2 - entry1 - entry2 - entry1 - entry2 ...
**                               --------------    --------------    --------------
**                               group3 1st time   group3 2nd time   group3 3rd time
*/
typedef struct _layout_entry_t
{
    uint16_t id;             /* unique ID to identify the purpose for this entry */
    uint16_t attributes;     /* EADD/EEXTEND/EREMOVE... */
    uint32_t page_count;     /* map size in page. Biggest chunk = 2^32 pages = 2^44 bytes. */
    uint64_t rva;            /* map offset, relative to enclave base */
    uint32_t content_size;   /* if content_offset = 0, content_size is the initial data to fill the whole page. */
    uint32_t content_offset; /* offset to the initial content, relative to metadata */
    si_flags_t si_flags;     /* security info, R/W/X, SECS/TCS/REG/VA */
} layout_entry_t;

typedef struct _layout_group_t
{
    uint16_t id;          /* unique ID to identify the purpose for this entry */
    uint16_t entry_count; /* reversely count entry_count entries for the group loading. */
    uint32_t load_times;  /* the repeated times of loading */
    uint64_t load_step;   /* the group size. the entry load rva should be adjusted with the load_step */
                          /* rva = entry.rva + group.load_step * load_times */
    uint32_t reserved[4];
} layout_group_t;

typedef union _layout_t
{
    layout_entry_t entry;
    layout_group_t group;
} layout_t;

typedef struct _attributes_t
{
    uint64_t flags;
    uint64_t xfrm;
} sgx_attributes_t;

typedef struct _data_directory_t
{
    uint32_t offset;
    uint32_t size;
} data_directory_t;

typedef enum
{
    DIR_PATCH,
    DIR_LAYOUT,
    DIR_NUM,
} dir_index_t;

typedef struct _metadata_t
{
    uint64_t magic_num;            /* The magic number identifying the file as a signed enclave image */
    uint64_t version;              /* The metadata version */
    uint32_t size;                 /* The size of this structure */
    uint32_t tcs_policy;           /* TCS management policy */
    uint32_t ssa_frame_size;       /* The size of SSA frame in page */
    uint32_t max_save_buffer_size; /* Max buffer size is 2632 */
    uint32_t desired_misc_select;
    uint32_t tcs_min_pool;       /* TCS min pool*/
    uint64_t enclave_size;       /* enclave virtual size */
    sgx_attributes_t attributes; /* XFeatureMask to be set in SECS. */
    uint8_t enclave_css[1808];   /* The enclave signature */
    data_directory_t dirs[DIR_NUM];
    uint8_t data[18592];
} metadata_t;

class SGXSanEnclaveConfigReader
{
public:
    SGXSanEnclaveConfigReader(uint64_t enclave_load_addr) : m_enclave_load_addr(enclave_load_addr) {}

    bool collect_layout_infos(const char *enclave_filename);

    bool shallow_poison_senitive();

private:
    const Elf64_Shdr *get_section(const Elf64_Ehdr *elf_hdr,
                                  section_filter_f f,
                                  const void *user_data);

    const Elf64_Shdr *get_section_by_name(const Elf64_Ehdr *elf_hdr, const char *name);

    bool get_meta_property(const void *start_addr, Elf64_Ehdr *elf_hdr, uint64_t &meta_offset, uint64_t &meta_block_size);

    bool get_layout_info(const uint64_t start_rva, layout_entry_t *layout);

    bool get_layout_infos(layout_t *layout_start, layout_t *layout_end, uint64_t delta);

    bool get_metadata(void *file_map_addr, metadata_t **metadata);

    uint64_t m_enclave_load_addr;
    // rva and page_count
    std::vector<std::pair<uint64_t, uint32_t>> m_sgxsan_guard_list;
    std::vector<std::pair<uint64_t, uint32_t>> m_sgxsan_tcs_list;
    std::vector<std::pair<uint64_t, uint32_t>> m_sgxsan_ssa_list;
};

#endif