#include "SensitivePoisoner.hpp"
#include "SGXSanAlignment.h"
#include "SGXSanPrintf.hpp"
#include "SGXSanCommonShadowMap.hpp"
#include "SGXSanCommonPoison.hpp"
#include <string>
#include <assert.h>

std::vector<std::pair<uint64_t, uint32_t>> SensitivePoisoner::m_guard_list,
    SensitivePoisoner::m_tcs_list,
    SensitivePoisoner::m_ssa_list,
    SensitivePoisoner::m_td_list,
    SensitivePoisoner::m_stack_max_list,
    SensitivePoisoner::m_stack_min_list,
    SensitivePoisoner::m_tcs_dyn_list,
    SensitivePoisoner::m_ssa_dyn_list,
    SensitivePoisoner::m_td_dyn_list,
    SensitivePoisoner::m_stack_dyn_max_list,
    SensitivePoisoner::m_stack_dyn_min_list;

bool SensitivePoisoner::get_layout_info(const uint64_t start_rva, layout_entry_t *layout)
{
    static int count = 0;
    (void)count;
    uint64_t rva = start_rva + layout->rva;
    assert(IsAligned(rva, 0x1000));
    SGXSAN_LOG("%d\t%s\n", ++count, __FUNCTION__);
    SGXSAN_LOG("\tEntry Id     = %4u, %-16s, ", layout->id, layout_id_str[layout->id & ~(GROUP_FLAG)]);
    SGXSAN_LOG("Page Count = %5u, ", layout->page_count);
    SGXSAN_LOG("Attributes = 0x%02X, ", layout->attributes);
    SGXSAN_LOG("Flags = 0x%016lX, ", layout->si_flags);
    SGXSAN_LOG("RVA = 0x%016lX -> ", layout->rva);
    SGXSAN_LOG("RVA = 0x%016lX\n", rva);
    // collect info for sgxsan
    if (layout->id == LAYOUT_ID_GUARD)
    {
        m_guard_list.push_back(std::make_pair(rva, layout->page_count));
    }
    else if (layout->id == LAYOUT_ID_TCS)
    {
        m_tcs_list.push_back(std::make_pair(rva, layout->page_count));
    }
    else if (layout->id == LAYOUT_ID_SSA)
    {
        m_ssa_list.push_back(std::make_pair(rva, layout->page_count));
    }
    else if (layout->id == LAYOUT_ID_TD)
    {
        m_td_list.push_back(std::make_pair(rva, layout->page_count));
    }
    else if (layout->id == LAYOUT_ID_STACK_MAX)
    {
        m_stack_max_list.push_back(std::make_pair(rva, layout->page_count));
    }
    else if (layout->id == LAYOUT_ID_STACK_MIN)
    {
        m_stack_min_list.push_back(std::make_pair(rva, layout->page_count));
    }
    else if (layout->id == LAYOUT_ID_TCS_DYN)
    {
        m_tcs_dyn_list.push_back(std::make_pair(rva, layout->page_count));
    }
    else if (layout->id == LAYOUT_ID_SSA_DYN)
    {
        m_ssa_dyn_list.push_back(std::make_pair(rva, layout->page_count));
    }
    else if (layout->id == LAYOUT_ID_TD_DYN)
    {
        m_td_dyn_list.push_back(std::make_pair(rva, layout->page_count));
    }
    else if (layout->id == LAYOUT_ID_STACK_DYN_MAX)
    {
        m_stack_dyn_max_list.push_back(std::make_pair(rva, layout->page_count));
    }
    else if (layout->id == LAYOUT_ID_STACK_DYN_MIN)
    {
        m_stack_dyn_min_list.push_back(std::make_pair(rva, layout->page_count));
    }
    return true;
}

bool SensitivePoisoner::get_layout_infos(layout_t *layout_start, layout_t *layout_end, uint64_t delta)
{
    for (layout_t *layout = layout_start; layout < layout_end; layout++)
    {
        SGXSAN_LOG("%s, step = 0x%016lX\n", __FUNCTION__, delta);

        if (!IS_GROUP_ID(layout->group.id))
        {
            if (!get_layout_info(delta, &layout->entry))
            {
                return false;
            }
        }
        else
        {
            SGXSAN_LOG("\tEntry Id(%2u) = %4u, %-16s, ", 0, layout->entry.id, layout_id_str[layout->entry.id & ~(GROUP_FLAG)]);
            SGXSAN_LOG("Entry Count = %4u, ", layout->group.entry_count);
            SGXSAN_LOG("Load Times = %u,    ", layout->group.load_times);
            SGXSAN_LOG("LStep = 0x%016lX\n", layout->group.load_step);

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

void SensitivePoisoner::collect_layout_infos()
{
    if (m_guard_list.size() != 0)
    {
        // already collected
        return;
    }
    get_layout_infos(g_global_data.layout_table, g_global_data.layout_table + g_global_data.layout_entry_num, 0);
}

void SensitivePoisoner::do_poison(std::string title, std::vector<std::pair<uint64_t, uint32_t>> &list, uint64_t base_addr, bool do_poison)
{
    PRINTF("[%s]\n", title);
    for (auto ele : list)
    {
        // sensitive area should be well aligned
        PRINTF("\t\t[0x%lX, 0x%lX]=>[0x%lX, 0x%lX]\n", ele.first + base_addr, ele.first + base_addr + (ele.second << 12) - 1,
               MEM_TO_SHADOW(ele.first + base_addr), MEM_TO_SHADOW(ele.first + base_addr + (ele.second << 12) - 1));
        if (do_poison)
            FastPoisonShadow(ele.first + base_addr, ele.second << 12, kSGXSanSensitiveLayout);
    }
}

void SensitivePoisoner::show_layout_ex(std::string title, std::vector<std::pair<uint64_t, uint32_t>> &list1, std::vector<std::pair<uint64_t, uint32_t>> &list2, uint64_t base_addr)
{
    PRINTF("[%s]\n", title);
    for (size_t i = 0; i < list1.size(); i++)
    {
        std::pair<uint64_t, uint32_t> ele1 = list1[i];
        if (i < list2.size())
        {
            std::pair<uint64_t, uint32_t> ele2 = list2[i];
            assert(ele2.first < ele1.first);
            PRINTF("\t\t[0x%lX...0x%lX, 0x%lX]=>[0x%lX...0x%lX, 0x%lX]\n",
                   ele2.first + base_addr,
                   ele1.first + base_addr,
                   ele1.first + base_addr + (ele1.second << 12) - 1,
                   MEM_TO_SHADOW(ele2.first + base_addr),
                   MEM_TO_SHADOW(ele1.first + base_addr),
                   MEM_TO_SHADOW(ele1.first + base_addr + (ele1.second << 12) - 1));
        }
        else
        {
            PRINTF("\t\t[0x%lX, 0x%lX]=>[0x%lX, 0x%lX]\n",
                   ele1.first + base_addr,
                   ele1.first + base_addr + (ele1.second << 12) - 1,
                   MEM_TO_SHADOW(ele1.first + base_addr),
                   MEM_TO_SHADOW(ele1.first + base_addr + (ele1.second << 12) - 1));
        }
    }
}

bool SensitivePoisoner::shallow_poison_senitive()
{
    // collect_layout_infos();

    do_poison("Guard list", m_guard_list, g_enclave_base);
    do_poison("TCS list", m_tcs_list, g_enclave_base);
    do_poison("SSA list", m_ssa_list, g_enclave_base);
    do_poison("TD list", m_td_list, g_enclave_base, false);
    show_layout_ex("STACK list", m_stack_min_list, m_stack_max_list, g_enclave_base);

    do_poison("TCS_DYN list", m_tcs_dyn_list, g_enclave_base);
    do_poison("SSA_DYN list", m_ssa_dyn_list, g_enclave_base);
    do_poison("TD_DYN list", m_td_dyn_list, g_enclave_base, false);
    show_layout_ex("STACK_DYN list", m_stack_dyn_min_list, m_stack_dyn_max_list, g_enclave_base);

    return true;
}
