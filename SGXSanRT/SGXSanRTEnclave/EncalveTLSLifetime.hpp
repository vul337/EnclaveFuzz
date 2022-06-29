#pragma once

#if defined(__cplusplus)
extern "C" {
#endif
void EnclaveTLSConstructorAtTBridgeBegin();
void EnclaveTLSDestructorAtTBridgeEnd();
#if defined(__cplusplus)
}
#endif