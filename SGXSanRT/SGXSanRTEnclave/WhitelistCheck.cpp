#include <string>
#include <deque>
#include <mbusafecrt.h>
#include "WhitelistCheck.hpp"
#include "SGXSanPrintf.hpp"
#include "PoisonCheck.hpp"
#include "SGXSanCommonShadowMap.hpp"

#define FUNC_NAME_MAX_LEN 127
#define CONTROL_FETCH_QUEUE_MAX_SIZE 3

struct FetchInfo
{
    const void *start_addr = nullptr;
    size_t size = 0;
    char parent_func[FUNC_NAME_MAX_LEN + 1] = {0};
    bool used_to_cmp = false;
};

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
    static std::pair<std::map<const void *, size_t>::iterator, bool> add(const void *ptr, size_t size);
    static std::pair<std::map<const void *, size_t>::iterator, bool> add_global(const void *ptr, size_t size);
    static std::tuple<const void *, size_t, bool /* is_at_global? */> query(const void *ptr, size_t size);
    static std::pair<const void *, size_t> query_global(const void *ptr, size_t size);
    static bool global_propagate(const void *ptr);
    static void active();
    static void deactive();
    static bool double_fetch_detect(const void *ptr, size_t size, bool used_to_cmp, char *parent_func);

private:
    static __thread std::map<const void *, size_t> *m_whitelist;
    // used in nested ecall-ocall case
    static __thread bool m_whitelist_active;
    static __thread std::deque<FetchInfo> *m_control_fetchs;
    static std::map<const void *, size_t> m_global_whitelist;
    static pthread_rwlock_t m_rwlock_global_whitelist;
};

__thread std::map<const void *, size_t> *WhitelistOfAddrOutEnclave::m_whitelist;
__thread bool WhitelistOfAddrOutEnclave::m_whitelist_active;
__thread std::deque<FetchInfo> *WhitelistOfAddrOutEnclave::m_control_fetchs;
std::map<const void *, size_t> WhitelistOfAddrOutEnclave::m_global_whitelist;
pthread_rwlock_t WhitelistOfAddrOutEnclave::m_rwlock_global_whitelist = PTHREAD_RWLOCK_INITIALIZER;

// add at bridge
void WhitelistOfAddrOutEnclave::init()
{
    m_whitelist = new std::map<const void *, size_t>();
    m_whitelist_active = false;
    m_control_fetchs = new std::deque<FetchInfo>();
}

void WhitelistOfAddrOutEnclave::destroy()
{
    delete m_whitelist;
    m_whitelist = nullptr;
    delete m_control_fetchs;
    m_control_fetchs = nullptr;
    m_whitelist_active = false;
}

void WhitelistOfAddrOutEnclave::iter(bool is_global)
{
    std::map<const void *, size_t> *whitelist = is_global ? &m_global_whitelist : m_whitelist;
    SGXSAN_TRACE("[Whitelist] [%s] ", is_global ? "Global" : "Thread");
    for (auto it = whitelist->begin(); it != whitelist->end(); it++)
    {
        SGXSAN_TRACE("0x%p(0xllx) ", it->first, it->second);
    }
    SGXSAN_TRACE(" %s", "\n");
}

std::pair<std::map<const void *, size_t>::iterator, bool> WhitelistOfAddrOutEnclave::add(const void *ptr, size_t size)
{
    assert(ptr && m_whitelist);
    assert(((uptr)ptr >= g_enclave_base + g_enclave_size) or ((uptr)ptr + size <= g_enclave_base));
    auto ret = m_whitelist->emplace(ptr, size);
    SGXSAN_TRACE("[Whitelist] [%s] [%s] 0x%p(0xllx)\n", "Thread", "+", ptr, size);
    // iter();
    return ret;
}

std::pair<std::map<const void *, size_t>::iterator, bool> WhitelistOfAddrOutEnclave::add_global(const void *ptr, size_t size)
{
    assert(ptr);
    pthread_rwlock_wrlock(&m_rwlock_global_whitelist);
    auto ret = m_global_whitelist.emplace(ptr, size);
    SGXSAN_TRACE("[Whitelist] [%s] [%s] 0x%p(0xllx)\n", "~Global~", "+", ptr, size);
    // iter(true);
    pthread_rwlock_unlock(&m_rwlock_global_whitelist);
    return ret;
}

// fetch must be a LoadInst
bool WhitelistOfAddrOutEnclave::double_fetch_detect(const void *ptr, size_t size, bool used_to_cmp, char *parent_func)
{
    assert(m_control_fetchs && ptr && size > 0);
    if (used_to_cmp)
    {
        // it's a fetch used to compare, maybe used to 'check'
        while (m_control_fetchs->size() >= CONTROL_FETCH_QUEUE_MAX_SIZE)
        {
            m_control_fetchs->pop_front();
        }
        FetchInfo info;
        info.start_addr = ptr;
        info.size = size;
        info.used_to_cmp = used_to_cmp;
        strncpy(info.parent_func, parent_func, std::min((size_t)FUNC_NAME_MAX_LEN, strlen(parent_func)));
        info.parent_func[FUNC_NAME_MAX_LEN] = 0;
        m_control_fetchs->push_back(info);
        return false;
    }
    else
    {
        bool result = false;
        // it's a non-compared fetch, maybe used to 'use'
        for (auto &control_fetch : *m_control_fetchs)
        {
            // if parent function name is not known, assume at same function and only check overlap
            bool at_same_func = true;
            if (parent_func)
                at_same_func = strncmp(control_fetch.parent_func, parent_func,
                                       std::min((size_t)FUNC_NAME_MAX_LEN, strlen(parent_func))) == 0;
            bool is_overlap = RangesOverlap((const char *)control_fetch.start_addr, control_fetch.size,
                                            (const char *)ptr, size);
            result = result || (at_same_func && is_overlap);
        }
        return result;
    }
}

// return value:
// 1) query failed at thread and global whitelist
// 2) query success at thread whitelist (global whitelist may also contain this info)
// 3) query success at global whitelist (thread whitelist do not contain this info)
std::tuple<const void *, size_t, bool> WhitelistOfAddrOutEnclave::query(const void *ptr, size_t size)
{
    assert(m_whitelist && ptr && (((uptr)ptr >= g_enclave_base + g_enclave_size) or ((uptr)ptr + size <= g_enclave_base)));
    if (!m_whitelist_active)
        return std::tuple<const void *, size_t, bool>(nullptr, 1, false);

    SGXSAN_TRACE("[Whitelist] [%s] [%s] 0x%p(0xllx)\n", "Thread", "?", ptr, size);
    // iter();
    std::map<const void *, size_t>::iterator it;
    std::tuple<const void *, size_t, bool> ret, false_ret = std::tuple<const void *, size_t, bool>(nullptr, 0, false);

    if (m_whitelist->size() == 0)
    {
        ret = false_ret;
        goto exit;
    }

    it = m_whitelist->lower_bound(ptr);

    if (LIKELY(it != m_whitelist->end() and it->first == ptr))
    {
        ret = it->second < size ? false_ret : std::tuple<const void *, size_t, bool>(it->first, it->second, false);
    }
    else if (it != m_whitelist->begin())
    {
        // get the element just blow query addr
        --it;
        ret = (uptr)it->first + it->second < (uptr)ptr + size ? false_ret : std::tuple<const void *, size_t, bool>(it->first, it->second, false);
    }
    else
    {
        // there is no <addr,size> pair can contain the query addr
        ret = false_ret;
    }
exit:
    if (ret == false_ret)
    {
        auto global_query_ret = query_global(ptr, size);
        ret = std::tuple<const void *, size_t, bool>(global_query_ret.first, global_query_ret.second, true);
    }

    return ret;
}

std::pair<const void *, size_t> WhitelistOfAddrOutEnclave::query_global(const void *ptr, size_t size)
{
    pthread_rwlock_rdlock(&m_rwlock_global_whitelist);
    SGXSAN_TRACE("[Whitelist] [%s] [%s] 0x%p(0xllx)\n", "~Global~", "?", ptr, size);
    // iter(true);
    std::map<const void *, size_t>::iterator it;
    std::pair<const void *, size_t> ret, false_ret = std::pair<const void *, size_t>(nullptr, 0);

    if (m_global_whitelist.size() == 0)
    {
        ret = false_ret;
        goto exit;
    }

    it = m_global_whitelist.lower_bound(ptr);

    if (LIKELY(it != m_global_whitelist.end() and it->first == ptr))
    {
        ret = it->second < size ? false_ret : std::pair<const void *, size_t>(it->first, it->second);
    }
    else if (it != m_global_whitelist.begin())
    {
        // get the element just blow query addr
        --it;
        ret = (uptr)it->first + it->second < (uptr)ptr + size ? false_ret : std::pair<const void *, size_t>(it->first, it->second);
    }
    else
    {
        // there is no <addr,size> pair can contain the query addr
        ret = false_ret;
    }
exit:
    pthread_rwlock_unlock(&m_rwlock_global_whitelist);
    return ret;
}

// input ptr may be in Enclave or out of Enclave
bool WhitelistOfAddrOutEnclave::global_propagate(const void *ptr)
{
    if (((uptr)ptr >= g_enclave_base) and ((uptr)ptr < g_enclave_base + g_enclave_size))
        return true;
    const void *find_start = nullptr;
    size_t find_size = 0;
    bool is_at_global = false;
    std::tie(find_start, find_size, is_at_global) = query(ptr, 1);
    assert(((uptr)find_start >= g_enclave_base + g_enclave_size) or ((uptr)find_start + find_size <= g_enclave_base));
    if (is_at_global == false && find_size != 0 /* return case 2 */)
    {
        SGXSAN_TRACE("[Whitelist] [Thread] => 0x%p => [~Global~]\n", ptr);
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

void WhitelistOfAddrOutEnclave_add(const void *start, size_t size)
{
    ABORT_ASSERT(WhitelistOfAddrOutEnclave::add(start, size).second, "Insertion conflict?");
}

void WhitelistOfAddrOutEnclave_query_ex(const void *ptr, size_t size, bool is_write, bool used_to_cmp, char *parent_func)
{
    if (not is_write)
    {
        SGXSAN_WARNING(WhitelistOfAddrOutEnclave::double_fetch_detect(ptr, size, used_to_cmp, parent_func),
                       "[SGXSan] Detect Double-Fetch Situation");
    }
    WhitelistOfAddrOutEnclave_query(ptr, size);
}

void WhitelistOfAddrOutEnclave_query(const void *ptr, size_t size)
{
    size_t find_size;
    std::tie(std::ignore, find_size, std::ignore) = WhitelistOfAddrOutEnclave::query(ptr, size);
    size_t buf_size = 1024;
    char buf[buf_size];
    sprintf_s(buf, buf_size, "[SGXSan] Illegal access outside-enclave: 0x%p", ptr);
    SGXSAN_WARNING(find_size == 0, buf);
}

void WhitelistOfAddrOutEnclave_global_propagate(const void *addr)
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
