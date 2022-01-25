#include "EncalveTLSLifetime.hpp"
#include "SGXInternal.hpp"
#include "WhitelistCheck.hpp"
#include "ThreadFuncArgShadowStack.hpp"
#include "Quarantine.hpp"

__thread int64_t TLS_init_count;

void EnclaveTLSConstructorAtTBridgeBegin()
{
    if (TLS_init_count == 0)
    {
        // root ecall
        QuarantineCache::init();
        WhitelistOfAddrOutEnclave_init();
        init_thread_func_arg_shadow_stack();
    }
    TLS_init_count++;
    assert(TLS_init_count < 1024);
}

void EnclaveTLSDestructorAtTBridgeEnd()
{
    if (TLS_init_count == 1)
    {
        // root ecall
        WhitelistOfAddrOutEnclave_destroy();
        destroy_thread_func_arg_shadow_stack();
        QuarantineCache::destory();
    }
    TLS_init_count--;
    assert(TLS_init_count >= 0);
}