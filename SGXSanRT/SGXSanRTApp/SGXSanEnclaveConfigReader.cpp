#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include "SGXSanEnclaveConfigReader.hpp"
#include "SGXSanManifest.h"
#include "SGXSanCommonPoison.hpp"
#include "SGXSanDefs.h"
#include "PrintfSpeicification.h"

#ifndef ROUND_UP_TO
#define ROUND_UP_TO(x, align) (((x) + (align - 1)) & ~(align - 1))
#endif

#ifndef GET_PTR
#define GET_PTR(t, p, offset) reinterpret_cast<t *>(reinterpret_cast<size_t>(p) + static_cast<size_t>(offset))
#endif

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

#define METADATA_MAGIC 0x86A80294635D0E4CULL
#define META_DATA_MAKE_VERSION(major, minor) (((uint64_t)major) << 32 | minor)
#define MAJOR_VERSION_OF_METADATA(version) (((uint64_t)version) >> 32)
#define MINOR_VERSION_OF_METADATA(version) (((uint64_t)version) & 0xFFFFFFFF)
#define SGX_MAJOR_VERSION_GAP 10

typedef struct
{
    uint32_t namesz;
    uint32_t descsz;
    uint32_t type;
} Elf64_Note;

const char *layout_id_str[] = {
    "Undefined",
    "HEAP_MIN",
    "HEAP_INIT",
    "HEAP_MAX",
    "TCS",
    "TD",
    "SSA",
    "STACK_MAX",
    "STACK_MIN",
    "THREAD_GROUP",
    "GUARD",
    "HEAP_DYN_MIN",
    "HEAP_DYN_INIT",
    "HEAP_DYN_MAX",
    "TCS_DYN",
    "TD_DYN",
    "SSA_DYN",
    "STACK_DYN_MAX",
    "STACK_DYN_MIN",
    "THREAD_GROUP_DYN",
    "RSRV_MIN",
    "RSRV_INIT",
    "RSRV_MAX"};

static bool check_metadata_version(uint64_t urts_version, uint64_t metadata_version)
{
    //for metadata change, we have updated the metadata major version
    if (MAJOR_VERSION_OF_METADATA(urts_version) % SGX_MAJOR_VERSION_GAP < MAJOR_VERSION_OF_METADATA(metadata_version) % SGX_MAJOR_VERSION_GAP)
    {
        return false;
    }

    return true;
}

bool SGXSanEnclaveConfigReader::collect_layout_infos(const char *enclave_filename)
{
    int ret = false;
    void *file_map_addr = nullptr;
    uint64_t file_map_size = 0;
    metadata_t *metadata = nullptr;

    int fd = open(enclave_filename, O_RDONLY);
    if (fd == -1)
    {
        SGXSAN_TRACE("Couldn't open the enclave file, error = %d\n", errno);
        goto fail2;
    }
    struct stat st;
    memset(&st, 0, sizeof(st));
    if (-1 == fstat(fd, &st))
    {
        SGXSAN_TRACE("Couldn't get file status,  error code %x\n", errno);
        goto fail1;
    }
    file_map_addr = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (MAP_FAILED == file_map_addr)
    {
        SGXSAN_TRACE("Couldn't map view of file,  error code %x\n", errno);
        goto fail1;
    }
    file_map_size = st.st_size;

    if (!get_metadata(file_map_addr, &metadata))
    {
        goto exit;
    }

    ret = get_layout_infos(GET_PTR(layout_t, metadata, metadata->dirs[DIR_LAYOUT].offset),
                           GET_PTR(layout_t, metadata, metadata->dirs[DIR_LAYOUT].offset + metadata->dirs[DIR_LAYOUT].size),
                           0);
exit:
    munmap(file_map_addr, file_map_size);
fail1:
    close(fd);
fail2:
    return ret;
}

bool SGXSanEnclaveConfigReader::shallow_poison_senitive()
{
    SGXSAN_TRACE("[Guard list]\n");
    for (auto guard : m_sgxsan_guard_list)
    {
        // sensitive area should be well aligned
        SGXSAN_TRACE("\t\t[0x%lX, 0x%lX]=>[0x%lX, 0x%lX]\n", guard.first + m_enclave_load_addr, guard.first + m_enclave_load_addr + (guard.second << 12) - 1,
                     MEM_TO_SHADOW(guard.first + m_enclave_load_addr), MEM_TO_SHADOW(guard.first + m_enclave_load_addr + (guard.second << 12) - 1));
        FastPoisonShadow(guard.first + m_enclave_load_addr, guard.second << 12, kSGXSanShadowSensitive);
    }
    SGXSAN_TRACE("\n[TCS list]\n");
    for (auto tcs : m_sgxsan_tcs_list)
    {
        SGXSAN_TRACE("\t\t[0x%lX, 0x%lX]=>[0x%lX, 0x%lX]\n", tcs.first + m_enclave_load_addr, tcs.first + m_enclave_load_addr + (tcs.second << 12) - 1,
                     MEM_TO_SHADOW(tcs.first + m_enclave_load_addr), MEM_TO_SHADOW(tcs.first + m_enclave_load_addr + (tcs.second << 12) - 1));
        FastPoisonShadow(tcs.first + m_enclave_load_addr, tcs.second << 12, kSGXSanShadowSensitive);
    }
    SGXSAN_TRACE("\n[SSA list]\n");
    for (auto ssa : m_sgxsan_ssa_list)
    {
        SGXSAN_TRACE("\t\t[0x%lX, 0x%lX]=>[0x%lX, 0x%lX]\n", ssa.first + m_enclave_load_addr, ssa.first + m_enclave_load_addr + (ssa.second << 12) - 1,
                     MEM_TO_SHADOW(ssa.first + m_enclave_load_addr), MEM_TO_SHADOW(ssa.first + m_enclave_load_addr + (ssa.second << 12) - 1));
        FastPoisonShadow(ssa.first + m_enclave_load_addr, ssa.second << 12, kSGXSanShadowSensitive);
    }
    SGXSAN_TRACE("\n[TD list]\n");
    for (auto td : m_sgxsan_td_list)
    {
        SGXSAN_TRACE("\t\t[0x%lX, 0x%lX]=>[0x%lX, 0x%lX]\n", td.first + m_enclave_load_addr, td.first + m_enclave_load_addr + (td.second << 12) - 1,
                     MEM_TO_SHADOW(td.first + m_enclave_load_addr), MEM_TO_SHADOW(td.first + m_enclave_load_addr + (td.second << 12) - 1));
        // FastPoisonShadow(td.first + m_enclave_load_addr, td.second << 12, kSGXSanShadowSensitive);
    }
    SGXSAN_TRACE("\n[STACK list]\n");
    assert(m_sgxsan_stack_min_list.size() == m_sgxsan_stack_max_list.size());
    for (size_t i = 0; i < m_sgxsan_stack_min_list.size(); i++)
    {
        auto stack_min = m_sgxsan_stack_min_list[i], stack_max = m_sgxsan_stack_max_list[i];
        SGXSAN_TRACE("\t\t[0x%lX...0x%lX, 0x%lX]=>[0x%lX...0x%lX, 0x%lX]\n",
                     stack_max.first + m_enclave_load_addr,
                     stack_min.first + m_enclave_load_addr,
                     stack_min.first + m_enclave_load_addr + (stack_min.second << 12) - 1,
                     MEM_TO_SHADOW(stack_max.first + m_enclave_load_addr),
                     MEM_TO_SHADOW(stack_min.first + m_enclave_load_addr),
                     MEM_TO_SHADOW(stack_min.first + m_enclave_load_addr + (stack_min.second << 12) - 1));
        // FastPoisonShadow(td.first + m_enclave_load_addr, td.second << 12, kSGXSanShadowSensitive);
    }
    SGXSAN_TRACE("\n");
    return true;
}

static bool compare_section_name(const char *shstrtab,
                                 const Elf64_Shdr *shdr,
                                 const void *user_data)
{
    // `shstrtab + shdr->sh_name' is the section name.
    return (!strcmp(shstrtab + shdr->sh_name, (const char *)user_data));
}

const Elf64_Shdr *SGXSanEnclaveConfigReader::get_section(const Elf64_Ehdr *elf_hdr,
                                                         section_filter_f f,
                                                         const void *user_data)
{
    const Elf64_Shdr *shdr = GET_PTR(Elf64_Shdr, elf_hdr, elf_hdr->e_shoff);
    assert(sizeof(Elf64_Shdr) == elf_hdr->e_shentsize);

    // section header string table
    const char *shstrtab = GET_PTR(char, elf_hdr, shdr[elf_hdr->e_shstrndx].sh_offset);

    for (unsigned idx = 0; idx < elf_hdr->e_shnum; ++idx, ++shdr)
    {
        if (f(shstrtab, shdr, user_data))
            return shdr;
    }

    return nullptr;
}

const Elf64_Shdr *SGXSanEnclaveConfigReader::get_section_by_name(const Elf64_Ehdr *elf_hdr, const char *name)
{
    return get_section(elf_hdr, compare_section_name, name);
}

bool SGXSanEnclaveConfigReader::get_meta_property(const void *start_addr, Elf64_Ehdr *elf_hdr, uint64_t &meta_offset, uint64_t &meta_block_size)
{
    const Elf64_Shdr *shdr = get_section_by_name(elf_hdr, ".note.sgxmeta");
    if (shdr == nullptr)
    {
        SGXSAN_TRACE("ERROR: The enclave image should have '.note.sgxmeta' section\n");
        return false;
    }

    /* We require that enclaves should have .note.sgxmeta section to store the metadata information
     * We limit this section is used for metadata only and ISV should not extend this section.
     *
     * .note.sgxmeta layout:
     *
     * |  namesz         |
     * |  metadata size  |
     * |  type           |
     * |  name           |
     * |  metadata       |
     */

    const Elf64_Note *note = GET_PTR(Elf64_Note, start_addr, shdr->sh_offset);
    assert(note != NULL);

    if (shdr->sh_size != ROUND_UP_TO(sizeof(Elf64_Note) + note->namesz + note->descsz, shdr->sh_addralign))
    {
        SGXSAN_TRACE("ERROR: The '.note.sgxmeta' section size is not correct.\n");
        return false;
    }

    const char *meta_name = "sgx_metadata";
    if (note->namesz != (strlen(meta_name) + 1) || memcmp(GET_PTR(void, start_addr, shdr->sh_offset + sizeof(Elf64_Note)), meta_name, note->namesz))
    {
        SGXSAN_TRACE("ERROR: The note in the '.note.sgxmeta' section must be named as \"sgx_metadata\"\n");
        return false;
    }

    meta_offset = static_cast<uint64_t>(shdr->sh_offset + sizeof(Elf64_Note) + note->namesz);
    meta_block_size = note->descsz;
    return true;
}

bool SGXSanEnclaveConfigReader::get_layout_info(const uint64_t start_rva, layout_entry_t *layout)
{
    uint64_t rva = start_rva + layout->rva;
    assert(IsAligned(rva, 0x1000));
    // SGXSAN_TRACE("\t%s\n", __FUNCTION__);
    // SGXSAN_TRACE("\tEntry Id     = %4u, %-16s, ", layout->id, layout_id_str[layout->id & ~(GROUP_FLAG)]);
    // SGXSAN_TRACE("Page Count = %5u, ", layout->page_count);
    // SGXSAN_TRACE("Attributes = 0x%02X, ", layout->attributes);
    // SGXSAN_TRACE("Flags = 0x%016lX, ", layout->si_flags);
    // SGXSAN_TRACE("RVA = 0x%016lX -> ", layout->rva);
    // SGXSAN_TRACE("RVA = 0x%016lX\n", rva);
    // collect info for sgxsan
    if (layout->id == LAYOUT_ID_GUARD)
    {
        m_sgxsan_guard_list.push_back(std::make_pair(rva, layout->page_count));
    }
    else if (layout->id == LAYOUT_ID_TCS)
    {
        m_sgxsan_tcs_list.push_back(std::make_pair(rva, layout->page_count));
    }
    else if (layout->id == LAYOUT_ID_SSA)
    {
        m_sgxsan_ssa_list.push_back(std::make_pair(rva, layout->page_count));
    }
    else if (layout->id == LAYOUT_ID_TD)
    {
        m_sgxsan_td_list.push_back(std::make_pair(rva, layout->page_count));
    }
    else if (layout->id == LAYOUT_ID_STACK_MAX)
    {
        m_sgxsan_stack_max_list.push_back(std::make_pair(rva, layout->page_count));
    }
    else if (layout->id == LAYOUT_ID_STACK_MIN)
    {
        m_sgxsan_stack_min_list.push_back(std::make_pair(rva, layout->page_count));
    }
    return true;
}

bool SGXSanEnclaveConfigReader::get_layout_infos(layout_t *layout_start, layout_t *layout_end, uint64_t delta)
{
    for (layout_t *layout = layout_start; layout < layout_end; layout++)
    {
        // SGXSAN_TRACE("%s, step = 0x%016lX\n", __FUNCTION__, delta);

        if (!IS_GROUP_ID(layout->group.id))
        {
            if (!get_layout_info(delta, &layout->entry))
            {
                return false;
            }
        }
        else
        {
            // SGXSAN_TRACE("\tEntry Id(%2u) = %4u, %-16s, ", 0, layout->entry.id, layout_id_str[layout->entry.id & ~(GROUP_FLAG)]);
            // SGXSAN_TRACE("Entry Count = %4u, ", layout->group.entry_count);
            // SGXSAN_TRACE("Load Times = %u,    ", layout->group.load_times);
            // SGXSAN_TRACE("LStep = 0x%016lX\n", layout->group.load_step);

            uint64_t step = 0;
            for (uint32_t j = 0; j < layout->group.load_times; j++)
            {
                step += layout->group.load_step;
                if (!get_layout_infos(&layout[-layout->group.entry_count], layout, step))
                {
                    return false;
                }
            }
        }
    }
    return true;
}

static inline void cpuid(int *eax, int *ebx, int *ecx, int *edx)
{
    asm("cpuid"
        : "=a"(*eax),
          "=b"(*ebx),
          "=c"(*ecx),
          "=d"(*edx)
        : "0"(*eax), "2"(*ecx));
}

extern "C" bool is_cpu_support_edmm()
{
    int a[4] = {0, 0, 0, 0};

    //Check CPU EDMM capability by CPUID
    // eax=0
    cpuid(&a[0], &a[1], &a[2], &a[3]);
    if (a[0] < 0x12)
        return false;

    // eax=0 ecx=0x12
    a[0] = 0x12;
    a[2] = 0;
    cpuid(&a[0], &a[1], &a[2], &a[3]);
    if (!(a[0] & 1))
        return false;

    return ((a[0] & 2) != 0);
}

bool SGXSanEnclaveConfigReader::get_metadata(void *file_map_addr, metadata_t **metadata)
{
    uint64_t metadata_offset = 0, metadata_block_size = 0;
    metadata_t *target_metadata = nullptr;
    if (get_meta_property(file_map_addr, (Elf64_Ehdr *)file_map_addr, metadata_offset, metadata_block_size) == false)
    {
        return false;
    }
    // cannot support EDMM, adjust the possibly highest metadata version supported

    uint64_t urts_version = 0;
    // assume sgx driver up-to-date and support sgx2
    if (!is_cpu_support_edmm())
    {
        // cannot support EDMM, adjust the possibly highest metadata version supported
        urts_version = META_DATA_MAKE_VERSION(1 /* SGX_1_9_MAJOR_VERSION */, 4 /* SGX_1_9_MINOR_VERSION */);
    }
    do
    {
        *metadata = GET_PTR(metadata_t, file_map_addr, metadata_offset);
        if (*metadata == NULL)
        {
            return false;
        }
        if ((*metadata)->magic_num != METADATA_MAGIC)
        {
            break;
        }
        if (0 == (*metadata)->size)
        {
            SGXSAN_TRACE("ERROR: metadata's size can't be zero.\n");
            return false;
        }
        //check metadata version
        if (check_metadata_version(urts_version, (*metadata)->version) == true)
        {
            if (target_metadata == NULL ||
                target_metadata->version < (*metadata)->version)
            {
                target_metadata = *metadata;
            }
        }
        metadata_offset += (*metadata)->size; /*goto next metadata offset*/
    } while (1);

    if (target_metadata == NULL)
    {
        return false;
    }
    else
    {
        *metadata = target_metadata;
    }

    return true;
}