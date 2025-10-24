#ifndef SYSCALL_H
#define SYSCALL_H

#include <stdint.h>
#include "idt.h"

enum syscall_nr {
        SYS_READ  = 0,   // also accepts Linux ABI
        SYS_WRITE = 1,
        SYS_OPEN  = 2,
        SYS_CLOSE = 3,
        SYS_SEEK  = 4,
        SYS_SLEEP = 5,
        SYS_YIELD = 24,  // internal (keep, but use rarely)
        SYS_EXIT  = 60,
};

#ifdef __cplusplus
extern "C" {
#endif

void syscall_init();
// initialize x86_64 SYSCALL/SYSRET (MSR STAR/LSTAR/SFMASK, EFER.SCE)
void syscall_x64_init();
void syscall_dispatch(cpu_registers_t* regs);

#ifdef __cplusplus
}
#endif

#endif // SYSCALL_H 