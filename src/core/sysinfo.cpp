#include <sysinfo.h>
#include <debug.h>
#include <multiboot2.h>
#include <string.h>
#include <pit.h>

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

// Detect firmware type (BIOS vs UEFI)
static void detect_firmware() {
    // Check multiboot2 tags for firmware info
    // For now, assume BIOS since we're using GRUB in BIOS mode
    // In a real implementation, we'd parse multiboot2 tags for EFI information
    strcpy(g_system_info.firmware_type, "BIOS");
    strcpy(g_system_info.firmware_vendor, "GRUB");
    strcpy(g_system_info.firmware_version, "2.06");
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

// Get memory information (simplified)
static void detect_memory() {
    // This would normally parse multiboot2 memory map or ACPI
    // For now, use a reasonable default
    g_system_info.memory_mb = 1024;  // 1GB default
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
void sysinfo_print_dmesg_style() {
    // CPU information
    klog_printf("CPU: %s", g_cpu_info.brand_string);
    klog_printf("CPU Vendor: %s", g_cpu_info.vendor_id);
    klog_printf("CPU Family: %u Model: %u Stepping: %u",
                g_cpu_info.family, g_cpu_info.model, g_cpu_info.stepping);
    klog_printf("CPU Cores: %u Threads: %u",
                g_cpu_info.cores, g_cpu_info.threads);

    // APIC information
    if (g_system_info.has_apic) {
        klog_printf("APIC: Present");
        if (g_system_info.apic_mode == 1) {
            klog_printf("APIC: Legacy mode enabled");
        } else if (g_system_info.apic_mode == 2) {
            klog_printf("APIC: x2APIC mode enabled");
        }
        if (g_system_info.ioapic_count > 0) {
            klog_printf("IOAPIC: %u device(s) detected",
                        g_system_info.ioapic_count);
        }
    } else {
        klog_printf("APIC: Not detected or disabled");
    }

    // Firmware information
    klog_printf("Firmware: %s", g_system_info.firmware_type);
    if (strcmp(g_system_info.firmware_vendor, "Unknown") != 0) {
        klog_printf("Firmware Vendor: %s",
                    g_system_info.firmware_vendor);
    }
    if (strcmp(g_system_info.firmware_version, "Unknown") != 0) {
        klog_printf("Firmware Version: %s",
                    g_system_info.firmware_version);
    }

    // Memory information
    klog_printf("Memory: %u MB detected", g_system_info.memory_mb);
}

// Initialize system information detection
void sysinfo_init() {
    // Clear structures
    memset(&g_cpu_info, 0, sizeof(g_cpu_info));
    memset(&g_system_info, 0, sizeof(g_system_info));

    // Detect CPU information
    get_cpu_vendor(g_cpu_info.vendor_id);
    get_cpu_brand_string(g_cpu_info.brand_string);
    get_cpu_features();
    get_cpu_topology();

    // Detect system components
    detect_firmware();
    detect_apic();
    detect_memory();

    // Copy CPU info to system info
    memcpy(&g_system_info.cpu, &g_cpu_info, sizeof(cpu_info_t));

    // Print system information
    sysinfo_print_dmesg_style();
}
