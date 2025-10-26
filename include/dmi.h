#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

/* Scan SMBIOS/DMI tables, print BIOS/System/Board strings to klog.
   Returns 0 if entry point found, <0 otherwise. */
int dmi_scan(void);

/* Accessors (return empty string if not present) */
const char* dmi_get_bios_vendor(void);
const char* dmi_get_bios_version(void);
const char* dmi_get_bios_date(void);
const char* dmi_get_sys_vendor(void);
const char* dmi_get_product_name(void);
const char* dmi_get_product_sku(void);
const char* dmi_get_board_vendor(void);
const char* dmi_get_board_name(void);
const char* dmi_get_board_version(void);

#ifdef __cplusplus
}
#endif
