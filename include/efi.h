#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct { uint32_t Data1; uint16_t Data2; uint16_t Data3; uint8_t Data4[8]; } EFI_GUID;

static inline int guid_eq(const EFI_GUID* a,const EFI_GUID* b){
    const uint32_t* pa=(const uint32_t*)a; const uint32_t* pb=(const uint32_t*)b;
    return pa[0]==pb[0]&&pa[1]==pb[1]&&pa[2]==pb[2]&&pa[3]==pb[3];
}

typedef struct {
    EFI_GUID VendorGuid;
    void*    VendorTable;
} EFI_CONFIGURATION_TABLE;

typedef struct {
    char     _pad1[44]; // skip up to NumberOfTableEntries
    uint64_t NumberOfTableEntries;
    EFI_CONFIGURATION_TABLE* ConfigurationTable;
} EFI_SYSTEM_TABLE;

#ifdef __cplusplus
}
#endif