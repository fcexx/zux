#ifndef THREAD_H
#define THREAD_H
#include <stdint.h>
#include <context.h>

typedef enum {
    THREAD_READY,
    THREAD_RUNNING,
    THREAD_BLOCKED,
    THREAD_TERMINATED,
    THREAD_SLEEPING
} thread_state_t;

typedef struct thread {
    context_t context;
    uint64_t kernel_stack; // user mode (ring 3)
    uint64_t user_stack;   // user mode (ring 3)
    uint64_t user_rip;     // user mode (ring 3)
    uint8_t ring;          // user mode (ring 3)
    thread_state_t state;
    struct thread* next;
    uint64_t tid;
    char name[32];
    uint32_t sleep_until;  // Время пробуждения (в тиках таймера)
} thread_t;

extern int init;

void thread_init();
thread_t* thread_create(void (*entry)(void), const char* name);
void thread_yield();
void thread_schedule();
thread_t* thread_current();
void thread_stop(int pid);
thread_t* thread_get(int pid);
int thread_get_pid(const char* name);
void thread_block(int pid);
void thread_unblock(int pid);
int thread_get_state(int pid);
int thread_get_count();
void thread_sleep(uint32_t ms);

#endif // THREAD_H 