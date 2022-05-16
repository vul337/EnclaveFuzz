#include <string>
#include <mbusafecrt.h>
#include "WhitelistCheck.hpp"
#include "SGXSanPrintf.hpp"
#include "PoisonCheck.hpp"
#include "SGXSanCommonShadowMap.hpp"
// Init/Destroy at Enclave Tbridge Side, I didn't want to modify sgxsdk
// Active/Deactive at Enclave Tbridge Side to avoid nested calls, these operations are as close to Customized Enclave Side as possible
// Add at Enclave Tbridge Side to collect whitlist info
// Query at Customized Enclave Side for whitelist checking
// Global Proagate at Customized Enclave Side, which only consider global variables at Customized Enclave Side. This operation will use Add/Query
class WhitelistOfAddrOutEnclave
{
public:
    // add at bridge
    static void init();
    static void destroy();
    static void iter(bool is_global = false);
    static std::pair<std::map<uint64_t, uint64_t>::iterator, bool> add(uint64_t start, uint64_t size);
    static std::pair<std::map<uint64_t, uint64_t>::iterator, bool> add_global(uint64_t start, uint64_t size);
    static std::tuple<uint64_t, uint64_t, bool /* is_at_global? */> query(uint64_t start, uint64_t size,
                                                                          bool enable_double_fetch_check = false,
                                                                          bool is_write = false /* operation that access addr, used for double-fetch check */);
    static std::pair<uint64_t, uint64_t> query_global(uint64_t start, uint64_t size);
    static bool global_propagate(uint64_t addr);
    static void active();
    static void deactive();

private:
    static __thread std::map<uint64_t, uint64_t> *m_whitelist;
    // used in nested ecall-ocall case
    static __thread bool m_whitelist_active;
    static __thread uint64_t last_query_start, last_query_size;
    static std::map<uint64_t, uint64_t> m_global_whitelist;
    static pthread_rwlock_t m_rwlock_global_whitelist;
};

// __thread can not decorate class object, because __thread will not call class object's constructor
__thread std::map<uint64_t, uint64_t> *WhitelistOfAddrOutEnclave::m_whitelist;
__thread bool WhitelistOfAddrOutEnclave::m_whitelist_active;
__thread uint64_t WhitelistOfAddrOutEnclave::last_query_start, WhitelistOfAddrOutEnclave::last_query_size;
std::map<uint64_t, uint64_t> WhitelistOfAddrOutEnclave::m_global_whitelist;
pthread_rwlock_t WhitelistOfAddrOutEnclave::m_rwlock_global_whitelist = PTHREAD_RWLOCK_INITIALIZER;

// add at bridge
void WhitelistOfAddrOutEnclave::init()
{
    m_whitelist = new std::map<uint64_t, uint64_t>();
    m_whitelist_active = false;
    last_query_start = 0;
    last_query_size = 0;
}

void WhitelistOfAddrOutEnclave::destroy()
{
    delete m_whitelist;
    m_whitelist = nullptr;
}

void WhitelistOfAddrOutEnclave::iter(bool is_global)
{
    std::map<uint64_t, uint64_t> *whitelist = is_global ? &m_global_whitelist : m_whitelist;
    SGXSAN_TRACE("[Whitelist] [%s] ", is_global ? "Global" : "Thread");
    for (auto it = whitelist->begin(); it != whitelist->end(); it++)
    {
        SGXSAN_TRACE("0x%p(0x%p) ", (void *)it->first, (void *)it->second);
    }
    SGXSAN_TRACE(" %s", "\n");
}

std::pair<std::map<uint64_t, uint64_t>::iterator, bool> WhitelistOfAddrOutEnclave::add(uint64_t start, uint64_t size)
{
    assert(start >= g_enclave_base + g_enclave_size or start + size <= g_enclave_base);
    if (start == 0 || !m_whitelist)
    {
        return std::pair<std::map<uint64_t, uint64_t>::iterator, bool>(std::map<uint64_t, uint64_t>::iterator(), true);
    }
    auto ret = m_whitelist->emplace(start, size);
    SGXSAN_TRACE("[Whitelist] [%s] [%s] 0x%p(0x%p)\n", "Thread", "+", (void *)start, (void *)size);
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
    SGXSAN_TRACE("[Whitelist] [%s] [%s] 0x%p(0x%p)\n", "~Global~", "+", (void *)start, (void *)size);
    // iter(true);
    pthread_rwlock_unlock(&m_rwlock_global_whitelist);
    return ret;
}

std::tuple<uint64_t, uint64_t, bool> WhitelistOfAddrOutEnclave::query(uint64_t start, uint64_t size,
                                                                      bool enable_double_fetch_check,
                                                                      bool is_write)
{
    assert(start >= g_enclave_base + g_enclave_size or start + size <= g_enclave_base);
    if (!m_whitelist || (!m_whitelist_active))
    {
        return std::tuple<uint64_t, uint64_t, bool>(0, 1, false);
    }
    // double-fetch detect
    if (enable_double_fetch_check && not is_write)
    {
        // uint64_t a = last_query_start, b = last_query_size;/* used for debug, since sgx-gdb can not inspect __thread prefixed variable in sgx */
        if (last_query_start)
        {
            ABORT_ASSERT(!RangesOverlap((const char *)last_query_start, last_query_size, (const char *)start, size), "[SGXSan] Detect Double-Fetch Situation");
        }
        last_query_start = start;
        last_query_size = size;
    }
    SGXSAN_TRACE("[Whitelist] [%s] [%s] 0x%p(0x%p)\n", "Thread", "?", (void *)start, (void *)size);
    // iter();
    std::map<uint64_t, uint64_t>::iterator it;
    std::tuple<uint64_t, uint64_t, bool> ret, false_ret = std::tuple<uint64_t, uint64_t, bool>(0, 0, false);

    if (m_whitelist->size() == 0)
    {
        ret = false_ret;
        goto exit;
    }

    it = m_whitelist->lower_bound(start);

    if (LIKELY(it != m_whitelist->end() and it->first == start))
    {
        ret = it->second < size ? false_ret : std::tuple<uint64_t, uint64_t, bool>(it->first, it->second, false);
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
        ret = it->first + it->second < start + size ? false_ret : std::tuple<uint64_t, uint64_t, bool>(it->first, it->second, false);
        goto exit;
    }
exit:
    if (ret == false_ret)
    {
        auto global_query_ret = query_global(start, size);
        ret = std::tuple<uint64_t, uint64_t, bool>(global_query_ret.first, global_query_ret.second, true);
    }
    // return value:
    // 1) query failed at thread and global whitelist
    // 2) query success at thread whitelist (global whitelist may also contain this info)
    // 3) query success at global whitelist (thread whitelist do not contain this info)
    return ret;
}

std::pair<uint64_t, uint64_t> WhitelistOfAddrOutEnclave::query_global(uint64_t start, uint64_t size)
{
    pthread_rwlock_rdlock(&m_rwlock_global_whitelist);
    SGXSAN_TRACE("[Whitelist] [%s] [%s] 0x%p(0x%p)\n", "~Global~", "?", (void *)start, (void *)size);
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
    if (addr >= g_enclave_base and addr < g_enclave_base + g_enclave_size)
        return true;
    uint64_t find_start, find_size;
    bool is_at_global;
    std::tie(find_start, find_size, is_at_global) = query(addr, 1);
    assert(find_start >= g_enclave_base + g_enclave_size or find_start + find_size <= g_enclave_base);
    if (is_at_global == false && find_size != 0 /* return case 2 */)
    {
        SGXSAN_TRACE("[Whitelist] [Thread] => 0x%p => [~Global~]\n", (void *)addr);
        add_global(find_start, find_size);
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

// a list of c wrapper of WhitelistOfAddrOutEnclave that exported for use, class member function is inlined defaultly
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

void WhitelistOfAddrOutEnclave_query(uint64_t start, uint64_t size, bool is_write)
{
    uint64_t find_size;
    std::tie(std::ignore, find_size, std::ignore) = WhitelistOfAddrOutEnclave::query(start, size, true, is_write);
    size_t buf_size = 1024;
    char buf[buf_size];
    sprintf_s(buf, buf_size, "[SGXSan] Illegal access outside-enclave: 0x%p", (void *)start);
    SGXSAN_WARNING(find_size == 0, buf);
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
