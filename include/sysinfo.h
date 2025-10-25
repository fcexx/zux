#ifndef SYSINFO_H
#define SYSINFO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// CPU information structure
typedef struct {
    char vendor_id[13];        // CPU vendor string (12 chars + null)
    char brand_string[49];     // CPU brand string (48 chars + null)
    uint32_t family;           // CPU family
    uint32_t model;            // CPU model
    uint32_t stepping;         // CPU stepping
    uint32_t cores;            // Number of CPU cores
    uint32_t threads;          // Number of threads per core
    uint64_t features;         // CPU features bitmask
    uint32_t max_cpuid_level;  // Maximum CPUID level supported
} cpu_info_t;

// System information structure
typedef struct {
    cpu_info_t cpu;
    uint32_t memory_mb;        // Total memory in MB
    char firmware_type[16];    // "BIOS" or "UEFI"
    char firmware_vendor[64];  // Firmware vendor name
    char firmware_version[32]; // Firmware version
    uint8_t has_apic;          // 1 if Local APIC is present
    uint8_t has_x2apic;        // 1 if x2APIC is supported
    uint8_t apic_mode;         // Current APIC mode (0=disabled, 1=legacy, 2=x2apic)
    uint32_t ioapic_count;     // Number of IO APICs
} system_info_t;

// Feature flags (subset of CPUID feature bits)
#define CPU_FEATURE_FPU         (1ULL << 0)
#define CPU_FEATURE_MMX         (1ULL << 23)
#define CPU_FEATURE_SSE         (1ULL << 25)
#define CPU_FEATURE_SSE2        (1ULL << 26)
#define CPU_FEATURE_SSE3        (1ULL << 0)   // ECX bit 0
#define CPU_FEATURE_SSSE3       (1ULL << 9)   // ECX bit 9
#define CPU_FEATURE_SSE41       (1ULL << 19)  // ECX bit 19
#define CPU_FEATURE_SSE42       (1ULL << 20)  // ECX bit 20
#define CPU_FEATURE_AVX         (1ULL << 28)  // ECX bit 28
#define CPU_FEATURE_AVX2        (1ULL << 5)   // EBX bit 5 (EAX=7, ECX=0)
#define CPU_FEATURE_HYPERVISOR  (1ULL << 31)  // ECX bit 31 (EAX=1)
#define CPU_FEATURE_X2APIC      (1ULL << 21)  // ECX bit 21 (EAX=1)
#define CPU_FEATURE_TSC         (1ULL << 4)   // EDX bit 4 (EAX=1)
#define CPU_FEATURE_MSR         (1ULL << 5)   // EDX bit 5 (EAX=1)
#define CPU_FEATURE_PAE         (1ULL << 6)   // EDX bit 6 (EAX=1)
#define CPU_FEATURE_APIC        (1ULL << 9)   // EDX bit 9 (EAX=1)
#define CPU_FEATURE_PSE36       (1ULL << 17)  // EDX bit 17 (EAX=1)
#define CPU_FEATURE_PCLMULQDQ   (1ULL << 1)   // ECX bit 1 (EAX=1)
#define CPU_FEATURE_DTES64      (1ULL << 2)   // ECX bit 2 (EAX=1)
#define CPU_FEATURE_MONITOR     (1ULL << 3)   // ECX bit 3 (EAX=1)
#define CPU_FEATURE_VMX         (1ULL << 5)   // ECX bit 5 (EAX=1)
#define CPU_FEATURE_SMX         (1ULL << 6)   // ECX bit 6 (EAX=1)
#define CPU_FEATURE_EIST        (1ULL << 7)   // ECX bit 7 (EAX=1)
#define CPU_FEATURE_TM2         (1ULL << 8)   // ECX bit 8 (EAX=1)
#define CPU_FEATURE_CNXT_ID     (1ULL << 10)  // ECX bit 10 (EAX=1)
#define CPU_FEATURE_SDBG        (1ULL << 11)  // ECX bit 11 (EAX=1)
#define CPU_FEATURE_XTPR        (1ULL << 14)  // ECX bit 14 (EAX=1)
#define CPU_FEATURE_PDCM        (1ULL << 15)  // ECX bit 15 (EAX=1)
#define CPU_FEATURE_PCID        (1ULL << 17)  // ECX bit 17 (EAX=1)
#define CPU_FEATURE_DCA         (1ULL << 18)  // ECX bit 18 (EAX=1)
#define CPU_FEATURE_SSE4_1      (1ULL << 19)  // ECX bit 19 (EAX=1)
#define CPU_FEATURE_SSE4_2      (1ULL << 20)  // ECX bit 20 (EAX=1)
#define CPU_FEATURE_X2APIC      (1ULL << 21)  // ECX bit 21 (EAX=1)
#define CPU_FEATURE_MOVBE       (1ULL << 22)  // ECX bit 22 (EAX=1)
#define CPU_FEATURE_POPCNT      (1ULL << 23)  // ECX bit 23 (EAX=1)
#define CPU_FEATURE_TSC_DEADLINE (1ULL << 24) // ECX bit 24 (EAX=1)
#define CPU_FEATURE_AES         (1ULL << 25)  // ECX bit 25 (EAX=1)
#define CPU_FEATURE_XSAVE       (1ULL << 26)  // ECX bit 26 (EAX=1)
#define CPU_FEATURE_OSXSAVE     (1ULL << 27)  // ECX bit 27 (EAX=1)
#define CPU_FEATURE_AVX         (1ULL << 28)  // ECX bit 28 (EAX=1)
#define CPU_FEATURE_F16C        (1ULL << 29)  // ECX bit 29 (EAX=1)
#define CPU_FEATURE_RDRAND      (1ULL << 30)  // ECX bit 30 (EAX=1)
#define CPU_FEATURE_FPUCS       (1ULL << 13)  // ECX bit 13 (EAX=1)

// Initialize system information detection
void sysinfo_init();
void sysinfo_init_with_multiboot2(uint64_t multiboot2_info_ptr);

// Get CPU information
int sysinfo_get_cpu_info(cpu_info_t* info);

// Get complete system information
int sysinfo_get_system_info(system_info_t* info);

// Print system information in Unix dmesg style
void sysinfo_print_dmesg_style();

// CPUID helper functions
void cpuid(uint32_t leaf, uint32_t subleaf, uint32_t* eax, uint32_t* ebx, uint32_t* ecx, uint32_t* edx);
uint64_t rdmsr(uint32_t msr);
void wrmsr(uint32_t msr, uint64_t value);

// Feature checking functions
int cpu_has_feature(uint64_t feature);
int cpu_has_apic();
int cpu_has_x2apic();

#ifdef __cplusplus
}
#endif

#endif // SYSINFO_H
