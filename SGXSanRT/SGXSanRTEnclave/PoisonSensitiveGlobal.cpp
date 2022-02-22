#include "PoisonSensitiveGlobal.hpp"
#include "SGXSanCommonPoison.hpp"

void _PoisonSensitiveGlobal(__slsan_global *globalToBePolluted)
{
    PoisonShadow(globalToBePolluted->global_variable_addr,
                 globalToBePolluted->size,
                 globalToBePolluted->poison_value);
}

void PoisonSensitiveGlobal(__slsan_global *globalsToBePolluted, size_t count)
{
    for (uptr i = 0; i < count; i++)
    {
        _PoisonSensitiveGlobal(&globalsToBePolluted[i]);
    }
}