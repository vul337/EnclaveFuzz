#pragma once

#include "Poison.hpp"
#include "SGXSanRTCom.h"
#include "global_data.h"
#include <map>
#include <string>

class SGXLayoutPoisoner {
public:
  bool poison_senitive_layout() {
    collect_layout_infos();

    // Process normal
    do_poison("Guard", mLayoutInfos[LAYOUT_ID_GUARD], g_enclave_base);
    do_poison("TCS", mLayoutInfos[LAYOUT_ID_TCS], g_enclave_base);
    do_poison("SSA", mLayoutInfos[LAYOUT_ID_SSA], g_enclave_base);
    do_poison("TD", mLayoutInfos[LAYOUT_ID_TD], g_enclave_base, false);
    show_layout_ex("STACK", mLayoutInfos[LAYOUT_ID_STACK_MIN],
                   mLayoutInfos[LAYOUT_ID_STACK_MAX], g_enclave_base);

    // Process dynamic
    do_poison("TCS_DYN", mLayoutInfos[LAYOUT_ID_TCS_DYN], g_enclave_base);
    do_poison("SSA_DYN", mLayoutInfos[LAYOUT_ID_SSA_DYN], g_enclave_base);
    do_poison("TD_DYN", mLayoutInfos[LAYOUT_ID_TD_DYN], g_enclave_base, false);
    show_layout_ex("STACK_DYN", mLayoutInfos[LAYOUT_ID_STACK_DYN_MIN],
                   mLayoutInfos[LAYOUT_ID_STACK_DYN_MAX], g_enclave_base);

    return true;
  }

private:
  void collect_layout_infos() {
    if (mLayoutInfos[LAYOUT_ID_GUARD].size() > 0) {
      // already collected
      return;
    }
    get_layout_infos(
        g_global_data.layout_table,
        g_global_data.layout_table + g_global_data.layout_entry_num, 0);
  }

  bool get_layout_info(const uint64_t start_rva,
                       const volatile layout_entry_t *layout) {
    int count = 0;
    (void)count;
    uint64_t rva = start_rva + layout->rva;
    sgxsan_assert(IsAligned(rva, PAGE_SIZE));
    log_trace_np("%d\t%s\n", ++count, __FUNCTION__);
    log_trace_np("\tEntry Id     = %4u, %-16s, ", layout->id,
                 layout_id_str[layout->id & ~(GROUP_FLAG)]);
    log_trace_np("Page Count = %5u, ", layout->page_count);
    log_trace_np("Attributes = 0x%02X, ", layout->attributes);
    log_trace_np("Flags = 0x%016lX, ", layout->si_flags);
    log_trace_np("RVA = 0x%016lX -> ", layout->rva);
    log_trace_np("RVA = 0x%016lX\n", rva);

    // collect info for sgxsan
    mLayoutInfos[(uint16_t)layout->id][rva] = layout->page_count;
    return true;
  }

  bool get_layout_infos(const volatile layout_t *layout_start,
                        const volatile layout_t *layout_end, uint64_t delta) {
    for (const volatile layout_t *layout = layout_start; layout < layout_end;
         layout++) {
      log_trace_np("%s, step = 0x%016lX\n", __FUNCTION__, delta);

      if (!IS_GROUP_ID(layout->group.id)) {
        if (!get_layout_info(delta, &layout->entry)) {
          return false;
        }
      } else {
        log_trace_np("\tEntry Id(%2u) = %4u, %-16s, ", 0, layout->entry.id,
                     layout_id_str[layout->entry.id & ~(GROUP_FLAG)]);
        log_trace_np("Entry Count = %4u, ", layout->group.entry_count);
        log_trace_np("Load Times = %u,    ", layout->group.load_times);
        log_trace_np("LStep = 0x%016lX\n", layout->group.load_step);

        uint64_t step = 0;
        for (uint32_t j = 0; j < layout->group.load_times; j++) {
          step += layout->group.load_step;
          if (!get_layout_infos(&layout[-layout->group.entry_count], layout,
                                step)) {
            return false;
          }
        }
      }
    }
    return true;
  }

  void do_poison(std::string title,
                 std::map<uint64_t, uint32_t> &offsetAndPagesMap,
                 uint64_t base_addr, bool do_poison = true) {
    log_debug("[%s]\n", title.c_str());
    for (auto offsetAndPages : offsetAndPagesMap) {
      // sensitive area should be well aligned
      log_debug("\t\t[0x%lX, 0x%lX]=>[0x%lX, 0x%lX]\n",
                offsetAndPages.first + base_addr,
                offsetAndPages.first + base_addr +
                    (offsetAndPages.second << PAGE_SIZE_SHIFT) - 1,
                MEM_TO_SHADOW(offsetAndPages.first + base_addr),
                MEM_TO_SHADOW(offsetAndPages.first + base_addr +
                              (offsetAndPages.second << PAGE_SIZE_SHIFT) - 1));
      if (do_poison) {
        ShallowPoisonShadow(offsetAndPages.first + base_addr,
                            offsetAndPages.second << PAGE_SIZE_SHIFT,
                            kSGXSanSensitiveLayout);
      }
    }
  }

  void show_layout_ex(std::string title,
                      std::map<uint64_t, uint32_t> &offsetAndPagesMap1,
                      std::map<uint64_t, uint32_t> &offsetAndPagesMap2,
                      uint64_t base_addr) {
    sgxsan_assert(offsetAndPagesMap1.size() == offsetAndPagesMap2.size());
    log_debug("[%s]\n", title.c_str());
    auto it1 = offsetAndPagesMap1.begin();
    auto it2 = offsetAndPagesMap2.begin();
    for (; it1 != offsetAndPagesMap1.end() && it2 != offsetAndPagesMap2.end();
         it1++, it2++) {
      sgxsan_assert(it2->first < it1->first);
      log_debug("\t\t[0x%lX...0x%lX, 0x%lX]=>[0x%lX...0x%lX, 0x%lX]\n",
                it2->first + base_addr, it1->first + base_addr,
                it1->first + base_addr + (it1->second << PAGE_SIZE_SHIFT) - 1,
                MEM_TO_SHADOW(it2->first + base_addr),
                MEM_TO_SHADOW(it1->first + base_addr),
                MEM_TO_SHADOW(it1->first + base_addr +
                              (it1->second << PAGE_SIZE_SHIFT) - 1));
    }
  }

  std::map<uint16_t, std::map<uint64_t, uint32_t>> mLayoutInfos;
};
