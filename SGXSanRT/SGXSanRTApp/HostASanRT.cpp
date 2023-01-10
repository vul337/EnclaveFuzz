#include "SGXSanRTApp.h"

bool gHostASanInited = false;
extern "C" void __asan_init() {
  if (gHostASanInited)
    return;
  SGXSanInit();
  gHostASanInited = true;
}