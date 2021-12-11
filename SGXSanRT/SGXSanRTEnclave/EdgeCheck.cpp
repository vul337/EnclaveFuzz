#include "EdgeCheck.hpp"
#include "SGXSanCommonPoisonCheck.hpp"
#include "SGXSanCommonErrorReport.hpp"
#include "SGXSanPrintf.hpp"

// __thread can not decorate class object, because __thread will not call class object's constructor
__thread std::map<uint64_t, uint64_t> *WhitelistOfAddrOutEnclave::m_whitelist;
__thread int WhitelistOfAddrOutEnclave::m_whitelist_init_cnt;
__thread bool WhitelistOfAddrOutEnclave::m_whitelist_active;
std::map<uint64_t, uint64_t> WhitelistOfAddrOutEnclave::m_global_whitelist;
pthread_rwlock_t WhitelistOfAddrOutEnclave::m_rwlock_global_whitelist = PTHREAD_RWLOCK_INITIALIZER;

// add at bridge
void WhitelistOfAddrOutEnclave::init()
{
    // m_whitelist_init_cnt >= 1 means inited
    if (m_whitelist_init_cnt == 0)
    {
        m_whitelist = new std::map<uint64_t, uint64_t>();
        // SGXSAN_TRACE("[Whitelist] [Thread] [init] => %p\n", m_whitelist);
    }
    m_whitelist_init_cnt++;
    active();
    ABORT_ASSERT(m_whitelist_init_cnt < 1024, "[Whitelist] [Thread] Too much ecall nested");
}

void WhitelistOfAddrOutEnclave::destroy()
{
    // m_whitelist_init_cnt < 1 means uninited
    if (m_whitelist_init_cnt == 1)
    {
        // SGXSAN_TRACE("[Whitelist] [Thread] [destroy] %p => nullptr\n", m_whitelist);
        delete m_whitelist;
        m_whitelist = nullptr;
    }
    m_whitelist_init_cnt--;
    deactive();
    ABORT_ASSERT(m_whitelist_init_cnt >= 0, "[Whitelist] [Thread] Extra Destroy?");
}

void WhitelistOfAddrOutEnclave::iter(bool is_global)
{
    std::map<uint64_t, uint64_t> *whitelist = is_global ? &m_global_whitelist : m_whitelist;
    SGXSAN_TRACE("[Whitelist] [%s] ", is_global ? "Global" : "Thread");
    for (auto it = whitelist->begin(); it != whitelist->end(); it++)
    {
        SGXSAN_TRACE("0x%lx(0x%lx) ", it->first, it->second);
    }
    SGXSAN_TRACE(" %s", "\n");
}

std::pair<std::map<uint64_t, uint64_t>::iterator, bool> WhitelistOfAddrOutEnclave::add(uint64_t start, uint64_t size)
{
    if (start == 0 || m_whitelist_init_cnt < 1)
    {
        return std::pair<std::map<uint64_t, uint64_t>::iterator, bool>(std::map<uint64_t, uint64_t>::iterator(), true);
    }
    auto ret = m_whitelist->emplace(start, size);
    // SGXSAN_TRACE("[Whitelist] [%s] [%s] 0x%lx(0x%lx)\n", "Thread", "+", start, size);
    // iter();
    return ret;
}

std::pair<std::map<uint64_t, uint64_t>::iterator, bool> WhitelistOfAddrOutEnclave::add_global(uint64_t start, uint64_t size)
{
    if (start == 0)
    {
        return std::pair<std::map<uint64_t, uint64_t>::iterator, bool>(std::map<uint64_t, uint64_t>::iterator(), true);
    }
    pthread_rwlock_wrlock(&m_rwlock_global_whitelist);
    auto ret = m_global_whitelist.emplace(start, size);
    // SGXSAN_TRACE("[Whitelist] [%s] [%s] 0x%lx(0x%lx)\n", "~Global~", "+", start, size);
    // iter(true);
    pthread_rwlock_unlock(&m_rwlock_global_whitelist);
    return ret;
}

std::pair<uint64_t, uint64_t> WhitelistOfAddrOutEnclave::query(uint64_t start, uint64_t size)
{
    if (m_whitelist_init_cnt < 1 || (!m_whitelist_active))
    {
        return std::pair<uint64_t, uint64_t>(0, 1);
    }
    // SGXSAN_TRACE("[Whitelist] [%s] [%s] 0x%lx(0x%lx)\n", "Thread", "?", start, size);
    // iter();
    std::map<uint64_t, uint64_t>::iterator it;
    std::pair<uint64_t, uint64_t> ret, false_ret = std::pair<uint64_t, uint64_t>(0, 0);

    if (m_whitelist->size() == 0)
    {
        ret = false_ret;
        goto exit;
    }

    it = m_whitelist->lower_bound(start);

    if (LIKELY(it != m_whitelist->end() and it->first == start))
    {
        ret = it->second < size ? false_ret : std::pair<uint64_t, uint64_t>(it->first, it->second);
        goto exit;
    }

    if (it == m_whitelist->begin())
    {
        // there is no <addr,size> pair can contain the query addr
        ret = false_ret;
        goto exit;
    }
    else
    {
        // get the element just blow query addr
        --it;
        ret = it->first + it->second < start + size ? false_ret : std::pair<uint64_t, uint64_t>(it->first, it->second);
        goto exit;
    }
exit:
    if (ret == false_ret)
    {
        ret = query_global(start, size);
    }
    return ret;
}

std::pair<uint64_t, uint64_t> WhitelistOfAddrOutEnclave::query_global(uint64_t start, uint64_t size)
{
    pthread_rwlock_rdlock(&m_rwlock_global_whitelist);
    // SGXSAN_TRACE("[Whitelist] [%s] [%s] 0x%lx(0x%lx)\n", "~Global~", "?", start, size);
    // iter(true);
    std::map<uint64_t, uint64_t>::iterator it;
    std::pair<uint64_t, uint64_t> ret, false_ret = std::pair<uint64_t, uint64_t>(0, 0);

    if (m_global_whitelist.size() == 0)
    {
        ret = false_ret;
        goto exit;
    }

    it = m_global_whitelist.lower_bound(start);

    if (LIKELY(it != m_global_whitelist.end() and it->first == start))
    {
        ret = it->second < size ? false_ret : std::pair<uint64_t, uint64_t>(it->first, it->second);
        goto exit;
    }

    if (it == m_global_whitelist.begin())
    {
        // there is no <addr,size> pair can contain the query addr
        ret = false_ret;
        goto exit;
    }
    else
    {
        // get the element just blow query addr
        --it;
        ret = it->first + it->second < start + size ? false_ret : std::pair<uint64_t, uint64_t>(it->first, it->second);
        goto exit;
    }
exit:
    pthread_rwlock_unlock(&m_rwlock_global_whitelist);
    return ret;
}

bool WhitelistOfAddrOutEnclave::global_propagate(uint64_t addr)
{
    auto ret = query(addr, 1);
    if (ret.second != 0)
    {
        // SGXSAN_TRACE("[Whitelist] [Thread] => 0x%lx => [~Global~]\n", addr);
        add_global(ret.first, ret.second).second;
    }
    return true;
}

void WhitelistOfAddrOutEnclave::active()
{
    m_whitelist_active = true;
}

void WhitelistOfAddrOutEnclave::deactive()
{
    m_whitelist_active = false;
}

void sgxsan_edge_check(uint64_t ptr, uint64_t len, int cnt)
{
    SGXSAN_ELRANGE_CHECK_BEG(ptr, 0, len)
    if (__asan_region_is_poisoned(ptr, len, true))
    {
        PrintErrorAndAbort("[sgxsan_edge_check] 0x%lx point to sensitive area\n", ptr);
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
    SGXSAN_WARNING(WhitelistOfAddrOutEnclave::query(start, size).second != 0, "[SGXSan] Illegal access outside-enclave");
}

void WhitelistOfAddrOutEnclave_global_propagate(uint64_t addr)
{
    ABORT_ASSERT(WhitelistOfAddrOutEnclave::global_propagate(addr), "Fail to propagate to global whitelist");
}

void WhitelistOfAddrOutEnclave_active()
{
    WhitelistOfAddrOutEnclave::active();
}

void WhitelistOfAddrOutEnclave_deactive()
{
    WhitelistOfAddrOutEnclave::deactive();
}
