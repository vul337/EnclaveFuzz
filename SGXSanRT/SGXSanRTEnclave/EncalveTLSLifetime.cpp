#include "EncalveTLSLifetime.hpp"
#include "SGXInternal.hpp"
#include "WhitelistCheck.hpp"
#include "ThreadFuncArgShadowStack.hpp"

void EnclaveTLSConstructorAtTBridgeBegin()
{
    thread_data_t *td = get_thread_data();
    if (td->stack_base_addr == td->last_sp)
    {
        // root ecall
        WhitelistOfAddrOutEnclave_init();
        init_thread_func_arg_shadow_stack();
    }
}

void EnclaveTLSDestructorAtTBridgeEnd()
{
    thread_data_t *td = get_thread_data();
    if (td->stack_base_addr == td->last_sp)
    {
        // root ecall
        WhitelistOfAddrOutEnclave_destroy();
        destroy_thread_func_arg_shadow_stack();
    }
}