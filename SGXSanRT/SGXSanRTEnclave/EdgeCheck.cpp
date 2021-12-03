#include <map>
#include "EdgeCheck.hpp"
#include "SGXSanCommonPoisonCheck.hpp"
#include "SGXSanCommonErrorReport.hpp"
#include "SGXSanDefs.h"
#include "Printf.h"

class WhitelistOfAddrOutEnclave
{
public:
    // add at bridge
    static void init()
    {
        m_whitelist = new std::map<uint64_t, uint64_t>();
    }
    static void destroy()
    {
        delete m_whitelist;
    }
    static void iter()
    {
        SGXSAN_TRACE("[%s] ", "m_whitelist");
        for (auto it = m_whitelist->begin(); it != m_whitelist->end(); it++)
        {
            SGXSAN_TRACE("0x%lx(0x%lx) ", it->first, it->second);
        }
        SGXSAN_TRACE(" %s", "\n");
    }
    static std::pair<std::map<uint64_t, uint64_t>::iterator, bool> add(uint64_t start, uint64_t size)
    {
        if (start == 0)
        {
            return std::make_pair(std::map<uint64_t, uint64_t>::iterator(), true);
        }
        auto ret = m_whitelist->emplace(start, size);
        // SGXSAN_TRACE("[%s] 0x%lx(0x%lx)\n", "add", start, size);
        // iter();
        return ret;
    }
    static bool query(uint64_t start, uint64_t size)
    {
        // SGXSAN_TRACE("[%s] 0x%lx(0x%lx)\n", "query", start, size);
        // iter();
        if (m_whitelist->size() == 0)
        {
            return false;
        }

        auto it = m_whitelist->lower_bound(start);

        if (LIKELY(it != m_whitelist->end() and it->first == start))
        {
            return it->second < size ? false : true;
        }

        if (it == m_whitelist->begin())
        {
            // there is no <addr,size> pair can contain the query addr
            return false;
        }
        else
        {
            // get the element just blow query addr
            --it;
            return (it->first + it->second < start + size) ? false /* not large enough neither */ : true;
        }
    }

private:
    static __thread std::map<uint64_t, uint64_t> *m_whitelist;
};

// __thread can not decorate class object, because __thread will not call class object's constructor
__thread std::map<uint64_t, uint64_t> *WhitelistOfAddrOutEnclave::m_whitelist;

void sgxsan_user_check(uint64_t ptr, uint64_t len, int cnt)
{
    SGXSAN_ELRANGE_CHECK_BEG(ptr, 0, len)
    if (__asan_region_is_poisoned(ptr, len, true))
    {
        PrintErrorAndAbort("[sgxsan_user_check] 0x%lx point to sensitive area\n", ptr);
    }
    SGXSAN_ELRANGE_CHECK_MID
    //totally outside enclave, add to whitelist
    if (cnt == -1)
    {
        ABORT_ASSERT(WhitelistOfAddrOutEnclave::add(ptr, 1 << 12).second, "Insertion conflict?");
    }
    else
    {
        ABORT_ASSERT(WhitelistOfAddrOutEnclave::add(ptr, len * cnt).second, "Insertion conflict?");
    }
    SGXSAN_ELRANGE_CHECK_END;

    return;
}

// a list of c wrapper of WhitelistOfAddrOutEnclave, class member function is inlined defaultly
void WhitelistOfAddrOutEnclave_init()
{
    WhitelistOfAddrOutEnclave::init();
}

void WhitelistOfAddrOutEnclave_destroy()
{
    WhitelistOfAddrOutEnclave::destroy();
}

void WhitelistOfAddrOutEnclave_add(uint64_t start, uint64_t size)
{
    ABORT_ASSERT(WhitelistOfAddrOutEnclave::add(start, size).second, "Insertion conflict?");
}

void WhitelistOfAddrOutEnclave_query(uint64_t start, uint64_t size)
{
    ABORT_ASSERT(WhitelistOfAddrOutEnclave::query(start, size), "[SGXSan] Illegal access outside-enclave");
}