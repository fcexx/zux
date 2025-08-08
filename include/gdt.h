#ifndef GDT_H
#define GDT_H

#include <stdint.h>

void gdt_init();
void tss_set_rsp0(uint64_t rsp0);
void enter_user_mode(uint64_t user_entry, uint64_t user_stack_top);

// Expose user segment selectors
extern uint16_t KERNEL_CS;
extern uint16_t KERNEL_DS;
extern uint16_t USER_CS;
extern uint16_t USER_DS;

#endif // GDT_H 