#pragma once

#include "SGXInternal.hpp"
#include <vector>

class SensitivePoisoner
{
public:
    static bool shallow_poison_senitive();

private:
    static void collect_layout_infos();
    static bool get_layout_info(const uint64_t start_rva, layout_entry_t *layout);
    static bool get_layout_infos(layout_t *layout_start, layout_t *layout_end, uint64_t delta);
    static void do_poison(std::string title, std::vector<std::pair<uint64_t, uint32_t>> &list, uint64_t base_addr, bool do_poison = true);
    static void show_layout_ex(std::string title, std::vector<std::pair<uint64_t, uint32_t>> &list1, std::vector<std::pair<uint64_t, uint32_t>> &list2, uint64_t base_addr);
    static std::vector<std::pair<uint64_t, uint32_t>>
        m_guard_list,
        m_tcs_list,
        m_ssa_list,
        m_td_list,
        m_stack_max_list,
        m_stack_min_list,
        m_tcs_dyn_list,
        m_ssa_dyn_list,
        m_td_dyn_list,
        m_stack_dyn_max_list,
        m_stack_dyn_min_list;
};
