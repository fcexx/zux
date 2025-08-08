#ifndef SYSCALL_H
#define SYSCALL_H

#include <stdint.h>
#include <idt.h>

enum syscall_nr {
    SYS_YIELD = 0,
    SYS_WRITE = 1,
    SYS_EXIT  = 60,
};

#ifdef __cplusplus
extern "C" {
#endif

void syscall_init();
void syscall_dispatch(cpu_registers_t* regs);

#ifdef __cplusplus
}
#endif

#endif // SYSCALL_H 