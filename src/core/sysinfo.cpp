#include <sysinfo.h>
#include <debug.h>
#include <string.h>
#include <pit.h>
#include <stdint.h>
#include <multiboot2.h>

// Use multiboot2 constants from header file

// Global system information
static system_info_t g_system_info;
static cpu_info_t g_cpu_info;

// CPUID implementation
void cpuid(uint32_t leaf, uint32_t subleaf, uint32_t* eax, uint32_t* ebx, uint32_t* ecx, uint32_t* edx) {
    asm volatile(
        "cpuid"
        : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
        : "a"(leaf), "c"(subleaf)
    );
}

// MSR read/write functions
uint64_t rdmsr(uint32_t msr) {
    uint32_t low, high;
    asm volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
    return ((uint64_t)high << 32) | low;
}

void wrmsr(uint32_t msr, uint64_t value) {
    uint32_t low = value & 0xFFFFFFFF;
    uint32_t high = value >> 32;
    asm volatile("wrmsr" : : "a"(low), "d"(high), "c"(msr));
}

// Check if CPU supports specific feature
int cpu_has_feature(uint64_t feature) {
    return (g_cpu_info.features & feature) != 0;
}

// Check if CPU has APIC support
int cpu_has_apic() {
    return cpu_has_feature(CPU_FEATURE_APIC);
}

// Check if CPU has x2APIC support
int cpu_has_x2apic() {
    return cpu_has_feature(CPU_FEATURE_X2APIC);
}

// Get CPU vendor string
static void get_cpu_vendor(char* vendor) {
    uint32_t eax, ebx, ecx, edx;
    cpuid(0, 0, &eax, &ebx, &ecx, &edx);

    // Maximum CPUID level
    g_cpu_info.max_cpuid_level = eax;

    // Vendor string is in EBX, EDX, ECX
    memcpy(vendor, &ebx, 4);
    memcpy(vendor + 4, &edx, 4);
    memcpy(vendor + 8, &ecx, 4);
    vendor[12] = '\0';
}

// Get CPU brand string
static void get_cpu_brand_string(char* brand) {
    uint32_t eax, ebx, ecx, edx;

    // Brand string spans EAX=0x80000002 to EAX=0x80000004
    for (uint32_t i = 0; i < 3; i++) {
        cpuid(0x80000002 + i, 0, &eax, &ebx, &ecx, &edx);
        memcpy(brand + (i * 16), &eax, 4);
        memcpy(brand + (i * 16) + 4, &ebx, 4);
        memcpy(brand + (i * 16) + 8, &ecx, 4);
        memcpy(brand + (i * 16) + 12, &edx, 4);
    }
    brand[48] = '\0';

    // Clean up the string (remove leading/trailing spaces)
    char* start = brand;
    while (*start == ' ') start++;
    char* end = brand + 47;
    while (end > start && *end == ' ') end--;
    *(end + 1) = '\0';
    if (start != brand) {
        size_t len = strlen(start) + 1;
        memmove(brand, start, len);
    }
}

// Get CPU features and basic info
static void get_cpu_features() {
    uint32_t eax, ebx, ecx, edx;

    // Get processor info and feature bits (EAX=1)
    cpuid(1, 0, &eax, &ebx, &ecx, &edx);

    // Extract family, model, stepping
    uint32_t family = (eax >> 8) & 0xF;
    uint32_t model = (eax >> 4) & 0xF;
    uint32_t stepping = eax & 0xF;

    // Extended family and model (for newer CPUs)
    if (family == 0xF) {
        family += (eax >> 20) & 0xFF;
    }
    if (family == 0x6 || family == 0xF) {
        model += ((eax >> 16) & 0xF) << 4;
    }

    g_cpu_info.family = family;
    g_cpu_info.model = model;
    g_cpu_info.stepping = stepping;

    // Feature bits from EDX (EAX=1)
    g_cpu_info.features |= (uint64_t)(edx & (1 << 4))  << (4 - 4);   // TSC
    g_cpu_info.features |= (uint64_t)(edx & (1 << 5))  << (5 - 5);   // MSR
    g_cpu_info.features |= (uint64_t)(edx & (1 << 6))  << (6 - 6);   // PAE
    g_cpu_info.features |= (uint64_t)(edx & (1 << 9))  << (9 - 9);   // APIC
    g_cpu_info.features |= (uint64_t)(edx & (1 << 17)) << (17 - 17);  // PSE36

    // Feature bits from ECX (EAX=1)
    g_cpu_info.features |= (uint64_t)(ecx & (1 << 0))  << 0;    // SSE3
    g_cpu_info.features |= (uint64_t)(ecx & (1 << 1))  << 1;    // PCLMULQDQ
    g_cpu_info.features |= (uint64_t)(ecx & (1 << 2))  << 2;    // DTES64
    g_cpu_info.features |= (uint64_t)(ecx & (1 << 3))  << 3;    // MONITOR
    g_cpu_info.features |= (uint64_t)(ecx & (1 << 5))  << 5;    // VMX
    g_cpu_info.features |= (uint64_t)(ecx & (1 << 6))  << 6;    // SMX
    g_cpu_info.features |= (uint64_t)(ecx & (1 << 7))  << 7;    // EIST
    g_cpu_info.features |= (uint64_t)(ecx & (1 << 8))  << 8;    // TM2
    g_cpu_info.features |= (uint64_t)(ecx & (1 << 9))  << 9;    // SSSE3
    g_cpu_info.features |= (uint64_t)(ecx & (1 << 10)) << 10;   // CNXT_ID
    g_cpu_info.features |= (uint64_t)(ecx & (1 << 11)) << 11;   // SDBG
    g_cpu_info.features |= (uint64_t)(ecx & (1 << 14)) << 14;   // XTPR
    g_cpu_info.features |= (uint64_t)(ecx & (1 << 15)) << 15;   // PDCM
    g_cpu_info.features |= (uint64_t)(ecx & (1 << 17)) << 17;   // PCID
    g_cpu_info.features |= (uint64_t)(ecx & (1 << 18)) << 18;   // DCA
    g_cpu_info.features |= (uint64_t)(ecx & (1 << 19)) << 19;   // SSE4.1
    g_cpu_info.features |= (uint64_t)(ecx & (1 << 20)) << 20;   // SSE4.2
    g_cpu_info.features |= (uint64_t)(ecx & (1 << 21)) << 21;   // X2APIC
    g_cpu_info.features |= (uint64_t)(ecx & (1 << 22)) << 22;   // MOVBE
    g_cpu_info.features |= (uint64_t)(ecx & (1 << 23)) << 23;   // POPCNT
    g_cpu_info.features |= (uint64_t)(ecx & (1 << 24)) << 24;   // TSC_DEADLINE
    g_cpu_info.features |= (uint64_t)(ecx & (1 << 25)) << 25;   // AES
    g_cpu_info.features |= (uint64_t)(ecx & (1 << 26)) << 26;   // XSAVE
    g_cpu_info.features |= (uint64_t)(ecx & (1 << 27)) << 27;   // OSXSAVE
    g_cpu_info.features |= (uint64_t)(ecx & (1 << 28)) << 28;   // AVX
    g_cpu_info.features |= (uint64_t)(ecx & (1 << 29)) << 29;   // F16C
    g_cpu_info.features |= (uint64_t)(ecx & (1 << 30)) << 30;   // RDRAND
    g_cpu_info.features |= (uint64_t)(ecx & (1 << 31)) << 31;   // HYPERVISOR

    // Get extended features (EAX=7, ECX=0)
    cpuid(7, 0, &eax, &ebx, &ecx, &edx);
    g_cpu_info.features |= (uint64_t)(ebx & (1 << 5))  << 5;    // AVX2

    // Legacy features from EDX (EAX=1)
    g_cpu_info.features |= (uint64_t)(edx & (1 << 0))  << 0;    // FPU
    g_cpu_info.features |= (uint64_t)(edx & (1 << 23)) << 23;   // MMX
    g_cpu_info.features |= (uint64_t)(edx & (1 << 25)) << 25;   // SSE
    g_cpu_info.features |= (uint64_t)(edx & (1 << 26)) << 26;   // SSE2
}

// Get CPU topology (cores and threads)
static void get_cpu_topology() {
    uint32_t eax, ebx, ecx, edx;

    // Try to get topology using CPUID leaf 0xB (Intel) or 0x8000001E (AMD)
    cpuid(0xB, 0, &eax, &ebx, &ecx, &edx);
    if (ebx != 0) {
        // Intel topology
        g_cpu_info.cores = (ebx >> 16) & 0xFFFF;  // Number of logical processors at this level
        g_cpu_info.threads = ebx & 0xFFFF;        // Number of logical processors at next level
    } else {
        // Try AMD topology
        cpuid(0x8000001E, 0, &eax, &ebx, &ecx, &edx);
        if (eax != 0) {
            g_cpu_info.cores = (ebx >> 8) & 0xFF;
            g_cpu_info.threads = ebx & 0xFF;
        } else {
            // Fallback: assume single core with hyperthreading
            g_cpu_info.cores = 1;
            g_cpu_info.threads = 1;
        }
    }
}

// Helper function to get SMBIOS string
static char* get_smbios_string(uint8_t* structure, uint8_t index) {
    if (index == 0) return nullptr;

    uint8_t* strings_start = structure + structure[1];
    uint8_t current_index = 1;

    while (current_index < index && strings_start[0] != 0) {
        strings_start += strlen((char*)strings_start) + 1;
        current_index++;
    }

    if (current_index == index) {
        return (char*)strings_start;
    }

    return nullptr;
}

// Detect firmware type (BIOS vs UEFI)
static void detect_firmware(uint64_t multiboot2_info_ptr) {
    // Default values
    strcpy(g_system_info.firmware_type, "Unknown");
    strcpy(g_system_info.firmware_vendor, "Unknown");
    strcpy(g_system_info.firmware_version, "Unknown");

    if (multiboot2_info_ptr == 0) {
        return;
    }

    uint8_t* tag_ptr = (uint8_t*)(multiboot2_info_ptr + 8);
    while (1) {
        uint32_t tag_type = *(uint32_t*)tag_ptr;
        uint32_t tag_size = *(uint32_t*)(tag_ptr + 4);

        if (tag_type == 0) break;

        switch (tag_type) {
            case 2: {  // MULTIBOOT2_TAG_TYPE_LOADER_NAME
                // Bootloader name
                char* loader_string = (char*)(tag_ptr + 8);
                strncpy(g_system_info.firmware_vendor, loader_string, sizeof(g_system_info.firmware_vendor) - 1);
                g_system_info.firmware_vendor[sizeof(g_system_info.firmware_vendor) - 1] = '\0';
                break;
            }

            case 11:  // MULTIBOOT2_TAG_TYPE_EFI32
            case 12:  // MULTIBOOT2_TAG_TYPE_EFI64
            case 18:  // MULTIBOOT2_TAG_TYPE_EFI32_IH
            case 19:  // MULTIBOOT2_TAG_TYPE_EFI64_IH
            case 17:  // MULTIBOOT2_TAG_TYPE_EFI_MMAP
            case 21: {  // MULTIBOOT2_TAG_TYPE_EFI_BS_NOT_TERMINATED
                // EFI firmware detected
                strcpy(g_system_info.firmware_type, "UEFI");
                break;
            }

            case 13: {  // MULTIBOOT2_TAG_TYPE_SMBIOS
                // SMBIOS tables contain detailed firmware info
                strcpy(g_system_info.firmware_type, "BIOS");

                // SMBIOS version
                uint8_t major = *(uint8_t*)(tag_ptr + 8);
                uint8_t minor = *(uint8_t*)(tag_ptr + 9);
                {
                    char temp[16];
                    temp[0] = '0' + major / 10;
                    temp[1] = '0' + major % 10;
                    temp[2] = '.';
                    temp[3] = '0' + minor / 10;
                    temp[4] = '0' + minor % 10;
                    temp[5] = '\0';
                    strncpy(g_system_info.firmware_version, temp, sizeof(g_system_info.firmware_version) - 1);
                    g_system_info.firmware_version[sizeof(g_system_info.firmware_version) - 1] = '\0';
                }

                // Parse SMBIOS tables for vendor info
                uint8_t* smbios_tables = tag_ptr + 16;
                uint8_t* smbios_end = tag_ptr + tag_size;

                // Skip SMBIOS header and look for BIOS Information structure (type 0)
                if (smbios_tables + 4 <= smbios_end) {
                    uint8_t* table = smbios_tables + 4;  // Skip entry point header
                    while (table + 4 <= smbios_end) {
                        uint8_t type = table[0];
                        uint8_t length = table[1];

                        if (type == 0 && length >= 0x12) {  // BIOS Information structure
                            // BIOS Vendor (string at offset 4)
                            uint8_t vendor_idx = table[4];
                            if (vendor_idx > 0) {
                                char* vendor_str = get_smbios_string(table, vendor_idx);
                                if (vendor_str) {
                                    strncpy(g_system_info.firmware_vendor, vendor_str, sizeof(g_system_info.firmware_vendor) - 1);
                                    g_system_info.firmware_vendor[sizeof(g_system_info.firmware_vendor) - 1] = '\0';
                                }
                            }

                            // BIOS Version (string at offset 5)
                            uint8_t version_idx = table[5];
                            if (version_idx > 0) {
                                char* version_str = get_smbios_string(table, version_idx);
                                if (version_str) {
                                    strncpy(g_system_info.firmware_version, version_str, sizeof(g_system_info.firmware_version) - 1);
                                    g_system_info.firmware_version[sizeof(g_system_info.firmware_version) - 1] = '\0';
                                }
                            }

                            // BIOS Release Date (string at offset 8)
                            uint8_t release_idx = table[8];
                            if (release_idx > 0) {
                                char* release_str = get_smbios_string(table, release_idx);
                                if (release_str) {
                                    // Append release date to version
                                    strncat(g_system_info.firmware_version, " (", sizeof(g_system_info.firmware_version) - strlen(g_system_info.firmware_version) - 1);
                                    strncat(g_system_info.firmware_version, release_str, sizeof(g_system_info.firmware_version) - strlen(g_system_info.firmware_version) - 1);
                                    strncat(g_system_info.firmware_version, ")", sizeof(g_system_info.firmware_version) - strlen(g_system_info.firmware_version) - 1);
                                }
                            }
                            break;  // Found BIOS info, stop looking
                        }

                        // Move to next structure
                        if (type == 127) {  // End of table marker
                            break;
                        }

                        // Calculate next table position
                        uint8_t* strings_start = table + length;
                        while (strings_start < smbios_end && *(uint16_t*)strings_start != 0) {
                            strings_start += strlen((char*)strings_start) + 1;
                        }
                        strings_start += 2;  // Skip the double null terminator
                        table = strings_start;
                    }
                }
                break;
            }

            case 15: {  // MULTIBOOT2_TAG_TYPE_ACPI_NEW
                // ACPI RSDP - indicates modern firmware
                strcpy(g_system_info.firmware_type, "UEFI");
                strcpy(g_system_info.firmware_vendor, "ACPI-compatible");
                break;
            }

            case 14: {  // MULTIBOOT2_TAG_TYPE_ACPI_OLD
                // Legacy ACPI - indicates BIOS
                strcpy(g_system_info.firmware_type, "BIOS");
                strcpy(g_system_info.firmware_vendor, "Legacy BIOS");
                break;
            }
        }

        // Move to next tag
        tag_ptr += (tag_size + 7) & ~7;
    }
}

// Detect APIC information
static void detect_apic() {
    uint32_t eax, ebx, ecx, edx;

    g_system_info.has_apic = 0;
    g_system_info.has_x2apic = 0;
    g_system_info.apic_mode = 0;
    g_system_info.ioapic_count = 0;

    // Check if CPU supports APIC
    cpuid(1, 0, &eax, &ebx, &ecx, &edx);
    if (edx & (1 << 9)) {  // APIC bit
        g_system_info.has_apic = 1;

        // Check for x2APIC support
        if (ecx & (1 << 21)) {  // x2APIC bit
            g_system_info.has_x2apic = 1;

            // Check current APIC mode by reading IA32_APIC_BASE MSR (0x1B)
            uint64_t apic_base = rdmsr(0x1B);
            if (apic_base & (1 << 10)) {  // x2APIC mode
                g_system_info.apic_mode = 2;
            } else if (apic_base & (1 << 11)) {  // APIC enabled
                g_system_info.apic_mode = 1;
            }
        }
    }

    // For IO APIC count, we'd need ACPI MADT table parsing
    // For now, assume 1 IO APIC if we have APIC support
    if (g_system_info.has_apic) {
        g_system_info.ioapic_count = 1;
    }
}

// Get memory information from multiboot2
static void detect_memory(uint64_t multiboot2_info_ptr) {
    g_system_info.memory_mb = 1024;  // Default fallback

    if (multiboot2_info_ptr == 0) {
        return;
    }

    uint8_t* tag_ptr = (uint8_t*)(multiboot2_info_ptr + 8);
    while (1) {
        uint32_t tag_type = *(uint32_t*)tag_ptr;
        uint32_t tag_size = *(uint32_t*)(tag_ptr + 4);

        if (tag_type == 0) break;

        if (tag_type == 6) {  // MULTIBOOT2_TAG_TYPE_MMAP
            uint64_t total_memory = 0;
            uint32_t entry_size = *(uint32_t*)(tag_ptr + 8);
            uint32_t entry_count = (tag_size - 16) / entry_size;

            // Count available memory (type 1 = available RAM)
            multiboot2_tag_mmap_entry* entry = (multiboot2_tag_mmap_entry*)(tag_ptr + 16);
            for (uint32_t i = 0; i < entry_count; i++) {
                if (entry->type == 1) {  // Available RAM
                    total_memory += entry->len;
                }
                entry++;
            }

            g_system_info.memory_mb = total_memory / (1024 * 1024);
            break;
        }

        if (tag_type == 4) {  // MULTIBOOT2_TAG_TYPE_BASIC_MEMINFO
            uint64_t total_memory = (uint32_t)(*(uint32_t*)(tag_ptr + 8) + 1024) * 1024;  // Convert from KB to bytes
            g_system_info.memory_mb = total_memory / (1024 * 1024);
            break;
        }

        // Move to next tag
        tag_ptr += (tag_size + 7) & ~7;
    }
}

// Get CPU information
int sysinfo_get_cpu_info(cpu_info_t* info) {
    if (!info) return -1;

    memcpy(info, &g_cpu_info, sizeof(cpu_info_t));
    return 0;
}

// Get complete system information
int sysinfo_get_system_info(system_info_t* info) {
    if (!info) return -1;

    memcpy(info, &g_system_info, sizeof(system_info_t));
    return 0;
}

// Print system information in Unix dmesg style
void sysinfo_print_dmesg_style(uint64_t multiboot2_info_ptr) {
    // Command line (from multiboot2)
    if (multiboot2_info_ptr != 0) {
        uint8_t* tag_ptr = (uint8_t*)(multiboot2_info_ptr + 8);
        while (1) {
            uint32_t tag_type = *(uint32_t*)tag_ptr;
            uint32_t tag_size = *(uint32_t*)(tag_ptr + 4);

            if (tag_type == 0) break;

            if (tag_type == 1) {  // MULTIBOOT2_TAG_TYPE_CMDLINE
                char* cmdline_string = (char*)(tag_ptr + 8);
                klog_printf("Command line: %s", cmdline_string);
                break;
            }

            // Move to next tag
            tag_ptr += (tag_size + 7) & ~7;
        }
    }

    // CPU information
    klog_printf("cpuinfo: CPU: %s", g_cpu_info.brand_string);
    klog_printf("cpuinfo: CPU Vendor: %s", g_cpu_info.vendor_id);
    klog_printf("cpuinfo: CPU Family: %u Model: %u Stepping: %u",
                g_cpu_info.family, g_cpu_info.model, g_cpu_info.stepping);
    klog_printf("cpuinfo: CPU Cores: %u Threads: %u",
                g_cpu_info.cores, g_cpu_info.threads);

    // // CPU features
    // klog_printf("CPU Features:");
    // if (cpu_has_feature(CPU_FEATURE_FPU)) klog_printf(" FPU");
    // if (cpu_has_feature(CPU_FEATURE_MMX)) klog_printf(" MMX");
    // if (cpu_has_feature(CPU_FEATURE_SSE)) klog_printf(" SSE");
    // if (cpu_has_feature(CPU_FEATURE_SSE2)) klog_printf(" SSE2");
    // if (cpu_has_feature(CPU_FEATURE_SSE3)) klog_printf(" SSE3");
    // if (cpu_has_feature(CPU_FEATURE_SSSE3)) klog_printf(" SSSE3");
    // if (cpu_has_feature(CPU_FEATURE_SSE41)) klog_printf(" SSE4.1");
    // if (cpu_has_feature(CPU_FEATURE_SSE42)) klog_printf(" SSE4.2");
    // if (cpu_has_feature(CPU_FEATURE_AVX)) klog_printf(" AVX");
    // if (cpu_has_feature(CPU_FEATURE_AVX2)) klog_printf(" AVX2");
    // if (cpu_has_feature(CPU_FEATURE_HYPERVISOR)) klog_printf(" HYPERVISOR");
    // if (cpu_has_feature(CPU_FEATURE_APIC)) klog_printf(" APIC");
    // if (cpu_has_feature(CPU_FEATURE_X2APIC)) klog_printf(" x2APIC");
    // klog_printf("");

    // APIC information
    if (g_system_info.has_apic) {
        klog_printf("apicinfo: APIC: Present");
        if (g_system_info.apic_mode == 1) {
            klog_printf("apicinfo: APIC: Legacy mode enabled");
        } else if (g_system_info.apic_mode == 2) {
            klog_printf("apicinfo: APIC: x2APIC mode enabled");
        }
        if (g_system_info.ioapic_count > 0) {
            klog_printf("apicinfo: IOAPIC: %u device(s) detected",
                        g_system_info.ioapic_count);
        }
    } else {
        klog_printf("apicinfo: APIC: Not detected or disabled");
    }

    // Firmware information
    klog_printf("sysinfo: Firmware: %s", g_system_info.firmware_type);
    if (strcmp(g_system_info.firmware_vendor, "Unknown") != 0) {
        klog_printf("sysinfo: Firmware Vendor: %s",
                    g_system_info.firmware_vendor);
    }
    if (strcmp(g_system_info.firmware_version, "Unknown") != 0) {
        klog_printf("sysinfo: Firmware Version: %s",
                    g_system_info.firmware_version);
    }

    // Memory information
    klog_printf("sysinfo: Memory: %u MB detected", g_system_info.memory_mb);

    // Platform information
    if (strcmp(g_system_info.firmware_type, "UEFI") == 0) {
        klog_printf("sysinfo: Platform: UEFI system");
    } else if (strcmp(g_system_info.firmware_type, "BIOS") == 0) {
        klog_printf("sysinfo: Platform: Legacy BIOS system");
    } else {
        klog_printf("sysinfo: Platform: Unknown firmware");
    }
}

// Initialize system information detection
void sysinfo_init() {
    // Use default multiboot2 info (none)
    sysinfo_init_with_multiboot2(0);
}

// Initialize system information detection with multiboot2
void sysinfo_init_with_multiboot2(uint64_t multiboot2_info_ptr) {
    // Clear structures
    memset(&g_cpu_info, 0, sizeof(g_cpu_info));
    memset(&g_system_info, 0, sizeof(g_system_info));

    // Detect CPU information
    get_cpu_vendor(g_cpu_info.vendor_id);
    get_cpu_brand_string(g_cpu_info.brand_string);
    get_cpu_features();
    get_cpu_topology();

    // Detect system components
    detect_firmware(multiboot2_info_ptr);
    detect_apic();
    detect_memory(multiboot2_info_ptr);

    // Copy CPU info to system info
    memcpy(&g_system_info.cpu, &g_cpu_info, sizeof(cpu_info_t));

    // Print system information
    sysinfo_print_dmesg_style(multiboot2_info_ptr);
}
